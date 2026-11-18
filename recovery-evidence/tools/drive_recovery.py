#!/usr/bin/env python3
"""LaminaDB recovery evidence driver.

Runs the STOCK laminad binary (no kernel modification) through the recovery
states required for the evidence package:

  S1  confirmed commits -> SIGKILL crash -> restart (durability of confirmed)
  S2  ambiguous commit (no consumed response before crash) -> restart
      (ground truth resolved only by recovery: durable or not)
  S3  checkpoint + journal suffix composition (topology 1)
  S4  portable backup restore + new-lineage journal composition (topology 2),
      including change-cursor discontinuity (410) and same-sequence-number
      lineage divergence across the restore boundary
  S5  incomplete journal tail -> automatic truncation
  S6  complete-frame corruption (last frame and middle frame) -> startup refused

All durable artifacts are hashed. Only bounded raw data is retained in the
evidence directory (small API responses, hex excerpts, frame tables without
row payloads); full journals/images stay hash-only and are re-derivable by
re-running this script (see reproduce.sh).

Stdlib only. Usage:
  python3 -I drive_recovery.py --binary /path/to/laminad --out /path/to/evidence
"""
import argparse
import copy
import datetime
import hashlib
import json
import os
import pathlib
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zlib

SCHEMA = {
    "name": "spectra",
    "primary": "sample",
    "columns": [
        {"name": "sample", "type": "int"},
        {"name": "band", "type": "text"},
        {"name": "amplitude", "type": "int", "nullable": True},
        {"name": "valid", "type": "bool"},
    ],
}


def row(n, band=None, amplitude=None, valid=True):
    return {
        "sample": n,
        "band": band if band is not None else f"b{n}",
        "amplitude": n * 10 if amplitude is None else amplitude,
        "valid": valid,
    }


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def hex_dump(data, base=0, width=16):
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + off:08x}  {hexpart:<{width * 3}}  {ascii_}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Independent parsers (do not use the engine; re-decode the on-disk formats)
# ---------------------------------------------------------------------------

def parse_journal(path):
    """Decode journal.lmw bytes independently. Returns header, frame table
    (no row payloads), tail status, and file hash."""
    data = pathlib.Path(path).read_bytes()
    out = {
        "path": str(path),
        "file_size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "header_ok": False,
        "base": None,
        "frames": [],
        "tail": None,
        "parse_error": None,
    }
    try:
        if len(data) < 16 or data[:4] != b"LMW1":
            out["parse_error"] = "bad magic or truncated header"
            return out
        base = struct.unpack(">Q", data[4:12])[0]
        hdr_crc = struct.unpack(">I", data[12:16])[0]
        out["header_ok"] = zlib.crc32(data[:12]) == hdr_crc
  # CRC32-IEEE == zlib.crc32
        out["base"] = base
        off = 16
        expect = base + 1
        while off < len(data):
            if off + 8 > len(data):
                out["tail"] = {"kind": "partial-frame-header", "bytes": len(data) - off, "offset": off}
                break
            length, crc = struct.unpack(">II", data[off : off + 8])
            if length == 0 or length > 16 << 20:
                out["parse_error"] = f"invalid frame length {length} at {off}"
                return out
            if off + 8 + length > len(data):
                out["tail"] = {
                    "kind": "partial-frame-payload",
                    "bytes": len(data) - off,
                    "offset": off,
                    "declared_length": length,
                }
                break
            payload = data[off + 8 : off + 8 + length]
            crc_ok = zlib.crc32(payload) == crc
            frame = {"offset": off, "length": length, "crc_ok": crc_ok}
            if crc_ok:
                rec = json.loads(payload)
                frame["sequence"] = rec.get("sequence")
                frame["kind"] = rec.get("kind")
                frame["format"] = rec.get("format")
                frame["contiguous"] = rec.get("sequence") == expect
                if rec.get("kind") == "commit":
                    frame["transaction"] = rec.get("transaction")
                    frame["mutations"] = [
                        {"relation": m.get("relation"), "key": m.get("key"), "deleted": bool(m.get("deleted"))}
                        for m in rec.get("writes", [])
                    ]
                elif rec.get("kind") == "vacuum":
                    frame["horizon"] = rec.get("horizon")
                expect = rec.get("sequence", expect - 1) + 1
            else:
                frame["parse_note"] = "CRC mismatch: payload not decoded"
            out["frames"].append(frame)
            off += 8 + length
        out["end_offset"] = off
    except Exception as exc:  # evidence tool: record, never crash silently
        out["parse_error"] = f"{type(exc).__name__}: {exc}"
    return out


def _extract_payload_raw(text):
    """Return the exact raw substring of the top-level "payload" member."""
    key = text.index('"payload":') + len('"payload":')
    i = key
    while text[i] in " \t\r\n":
        i += 1
    start = i
    depth = 0
    in_str = False
    esc = False
    while i < len(text):
        c = text[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
        else:
            if c == '"':
                in_str = True
            elif c in "{[":
                depth += 1
            elif c in "}]":
                depth -= 1
                if depth == 0:
                    return text[start : i + 1]
        i += 1
    raise ValueError("unbalanced payload")


def parse_image_bytes(data):
    """Decode a checkpoint/backup envelope independently: verify SHA-256 over
    the exact payload bytes, then reconstruct visible rows at image.sequence."""
    text = data.decode("utf-8")
    env = json.loads(text)
    raw = _extract_payload_raw(text)
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    img = json.loads(raw)
    seq = img["sequence"]
    rows_by_table = {}
    for table, chains in img.get("store", {}).get("tables", {}).items():
        rows = []
        for key, chain in sorted(chains.items()):
            visible = None
            for v in chain:
                if v["sequence"] <= seq:
                    visible = v
                else:
                    break
            if visible is not None and not visible.get("deleted"):
                rows.append(visible["row"])
        rows_by_table[table] = sorted(rows, key=lambda r: r["sample"])
    return {
        "envelope_format": env.get("format"),
        "digest_header": env.get("sha256"),
        "digest_computed": digest,
        "digest_ok": digest == env.get("sha256"),
        "format": img.get("format"),
        "sequence": seq,
        "horizon": img.get("horizon"),
        "relations": sorted(img.get("catalog", {}).get("relations", {}).keys()),
        "rows_by_table": rows_by_table,
    }


# ---------------------------------------------------------------------------
# Evidence recorder
# ---------------------------------------------------------------------------

class Evidence:
    def __init__(self, out_dir):
        self.out = pathlib.Path(out_dir)
        if self.out.exists():
            # The evidence dir is this tool's own output. Only ever replace a
            # directory that looks like a previous run; refuse anything else.
            looks_ours = (self.out / "events.jsonl").exists() or (self.out / "manifest.json").exists()
            if not looks_ours and any(self.out.iterdir()):
                raise SystemExit(f"refusing to overwrite non-evidence directory: {self.out}")
            shutil.rmtree(self.out)
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / "api").mkdir(exist_ok=True)
        (self.out / "excerpts").mkdir(exist_ok=True)
        (self.out / "journal-tables").mkdir(exist_ok=True)
        self.t0_mono = time.monotonic()
        self.t0_wall = datetime.datetime.now(datetime.timezone.utc)
        self.events = []
        self.manifest = []
        self.claims = []
        self._event_seq = 0

    def mono_ms(self):
        return round((time.monotonic() - self.t0_mono) * 1000.0, 3)

    def event(self, actor, kind, **details):
        self._event_seq += 1
        entry = {
            "n": self._event_seq,
            "t_mono_ms": self.mono_ms(),
            "t_wall_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"),
            "actor": actor,
            "event": kind,
            "details": details,
        }
        self.events.append(entry)
        with open(self.out / "events.jsonl", "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def save_api(self, name, obj):
        rel = f"api/{name}.json"
        self._write_json(rel, obj)
        self.manifest.append(self._entry(rel, "raw", "HTTP API response/request capture"))
        return rel

    def save_excerpt(self, name, text, note):
        rel = f"excerpts/{name}.txt"
        self._write_text(rel, text)
        self.manifest.append(self._entry(rel, "excerpt", note))
        return rel

    def save_journal_table(self, name, parsed):
        rel = f"journal-tables/{name}.json"
        slim = {k: v for k, v in parsed.items() if k != "path"}
        self._write_json(rel, slim)
        self.manifest.append(self._entry(rel, "derived", "independent journal decode; frame metadata only, no row payloads"))
        return rel

    def hash_only(self, path, note):
        p = pathlib.Path(path)
        entry = {
            "original_path": str(p),
            "sha256": sha256_file(p),
            "bytes": p.stat().st_size,
            "retention": "hash-only",
            "note": note,
        }
        self.manifest.append(entry)
        return entry

    def hash_data(self, name, data, note):
        """Hash an in-memory byte state that no longer exists on disk (e.g. a
        journal state that recovery later truncated)."""
        entry = {
            "state": name,
            "sha256": hashlib.sha256(data).hexdigest(),
            "bytes": len(data),
            "retention": "hash-only",
            "note": note,
        }
        self.manifest.append(entry)
        return entry

    def claim(self, cid, statement, method, result, evidence, notes=""):
        self.claims.append(
            {"id": cid, "statement": statement, "method": method, "result": result, "evidence": evidence, "notes": notes}
        )

    def _entry(self, rel, retention, note):
        p = self.out / rel
        return {
            "path": rel,
            "sha256": sha256_file(p),
            "bytes": p.stat().st_size,
            "retention": retention,
            "note": note,
        }

    def _write_json(self, rel, obj):
        p = self.out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(obj, ensure_ascii=False, indent=1) + "\n")

    def _write_text(self, rel, text):
        p = self.out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


# ---------------------------------------------------------------------------
# Server session
# ---------------------------------------------------------------------------

class Session:
    def __init__(self, ev, binary, root, name, restore=None):
        self.ev = ev
        self.binary = str(binary)
        self.root = pathlib.Path(root)
        self.name = name
        self.restore = str(restore) if restore else None
        self.process = None
        self.log_path = None
        self.url = None
        self.port = None

    def start(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}/v1/lamina"
        args = [self.binary, "-data", str(self.root), "-listen", f"127.0.0.1:{self.port}"]
        if self.restore:
            args += ["-restore", self.restore]
        self.log_path = self.root.parent / f"{self.root.name}.{self.name}.stderr.log"
        self.log = open(self.log_path, "wb")
        self.process = subprocess.Popen(args, stdout=self.log, stderr=self.log)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"{self.name} exited early: {self.log_path.read_text(errors='replace')}")
            try:
                self.call("GET", "/health")
                self.ev.event(self.name, "server-ready", port=self.port, data_dir=str(self.root))
                return self
            except (OSError, urllib.error.URLError):
                time.sleep(0.03)
        raise RuntimeError(f"{self.name} did not become ready")

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        if self.log:
            self.log.close()
            self.log = None
        self.ev.event(self.name, "server-stopped-graceful", data_dir=str(self.root))

    def kill(self):
        """SIGKILL: simulates power loss / crash. No clean close, no checkpoint."""
        if self.process and self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=10)
        if self.log:
            self.log.close()
            self.log = None
        self.ev.event(self.name, "server-killed-sigkill", data_dir=str(self.root))

    def call(self, method, path, data=None, expect=200, raw=False):
        body = None if data is None else json.dumps(data, ensure_ascii=False).encode()
        req = urllib.request.Request(self.url + path, data=body, method=method, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                code, payload = resp.status, resp.read()
        except urllib.error.HTTPError as e:
            code, payload = e.code, e.read()
        if code != expect:
            raise RuntimeError(f"{method} {path}: expected {expect}, got {code}: {payload.decode(errors='replace')}")
        return payload if raw else json.loads(payload)

    def raw_call(self, method, path, data=None):
        body = None if data is None else json.dumps(data, ensure_ascii=False).encode()
        req = urllib.request.Request(self.url + path, data=body, method=method, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def begin(self):
        return self.call("POST", "/transactions", {}, 201)["id"]

    def put(self, tx, r):
        return self.call("POST", f"/transactions/{tx}/put", {"relation": "spectra", "row": r, "insert_only": False})

    def commit(self, tx):
        t_send = self.ev.mono_ms()
        out = self.call("POST", f"/transactions/{tx}/commit")
        t_recv = self.ev.mono_ms()
        return out, t_send, t_recv

    def rows(self, **kw):
        q = {"relation": "spectra", "limit": 10000}
        q.update(kw)
        return self.call("POST", "/query", q)["rows"]

    def stats(self):
        return self.call("GET", "/stats")


def sorted_rows(rows):
    return sorted(rows, key=lambda r: r["sample"])


# ---------------------------------------------------------------------------
# Main scenario
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--work", default=None, help="scratch dir for data dirs (default: mktemp)")
    args = ap.parse_args()

    binary = pathlib.Path(args.binary).resolve()
    if not binary.exists():
        sys.exit(f"binary not found: {binary}")
    ev = Evidence(args.out)
    work = pathlib.Path(args.work) if args.work else pathlib.Path(tempfile.mkdtemp(prefix="lamina-evidence-"))
    work.mkdir(parents=True, exist_ok=True)

    env_info = {
        "binary_path": str(binary),
        "binary_sha256": sha256_file(binary),
        "binary_bytes": binary.stat().st_size,
        "platform": " ".join(os.uname()),
        "python": sys.version.split()[0],
        "run_start_utc": ev.t0_wall.isoformat(timespec="milliseconds"),
        "kernel_note": "stock binary; faults injected externally only (SIGKILL, file append, byte flip on copies)",
    }
    try:
        env_info["git_head"] = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=binary.parent.parent, timeout=10
        ).stdout.strip()
    except Exception:
        env_info["git_head"] = None
    ev.event("driver", "environment", **env_info)

    model = {}          # sample -> row, only CONFIRMED commits applied
    model_at = {}       # sequence -> deepcopy(model) right after that sequence was confirmed
    commit_log = []     # client-side record of confirmed commits

    def confirm(sess, tx, label, applied_rows):
        """Commit via HTTP, record response + timing, apply to independent model."""
        out, t_send, t_recv = sess.commit(tx)
        seq = out["sequence"]
        for r in applied_rows:
            model[r["sample"]] = copy.deepcopy(r)
        model_at[seq] = copy.deepcopy(model)
        commit_log.append({"label": label, "sequence": seq, "response": out, "t_send_ms": t_send, "t_response_ms": t_recv})
        ev.event(sess.name, "commit-confirmed", label=label, sequence=seq, response=out, t_send_ms=t_send, t_response_ms=t_recv)
        return seq

    def check_rows(sess, tag, expected_model):
        got = sorted_rows(sess.rows())
        want = sorted_rows(list(expected_model.values()))
        ok = got == want
        safe = "".join(c if c.isalnum() else "-" for c in tag)
        ev.save_api(f"rows-{safe}", {"tag": tag, "match": ok, "row_count": len(got), "rows": got})
        ev.event(sess.name, "row-verification", tag=tag, match=ok, got_rows=len(got), want_rows=len(want))
        if not ok:
            ev.event(sess.name, "row-verification-MISMATCH", tag=tag, got=got, want=want)
        return ok, got

    # ------------------------------------------------------------------ S1
    dir_a = work / "A-source"
    s1 = Session(ev, binary, dir_a, "S1").start()
    rel_resp = s1.call("POST", "/relations", SCHEMA, 201)
    ev.save_api("s1-create-relation", {"status": 201, "body": rel_resp})
    ev.event("S1", "relation-created", note="DDL is its own durable record, sequence 1")

    tx = s1.begin(); [s1.put(tx, row(i)) for i in range(1, 6)]
    confirm(s1, tx, "seed-1..5", [row(i) for i in range(1, 6)])

    r1b = row(1, amplitude=99)
    tx = s1.begin(); s1.put(tx, r1b); s1.put(tx, row(6))
    seq_cursor = confirm(s1, tx, "row1-amp-99+row6", [r1b, row(6)])

    tx = s1.begin(); s1.put(tx, row(2, amplitude=200))
    seq_up = confirm(s1, tx, "row2-amp-200", [row(2, amplitude=200)])

    tx = s1.begin(); s1.put(tx, row(2, amplitude=20))
    seq_down = confirm(s1, tx, "row2-amp-back-20", [row(2, amplitude=20)])
    ev.event("S1", "masking-pair-complete",
             note="row2 amplitude 20->200->20 across two commits; value at the consumer cursor equals the current value",
             consumer_cursor=seq_cursor, transitions=[seq_up, seq_down],
             cursor_value=20, current_value=20)

    # -------------------------------------------------- S2 ambiguous commits
    ambiguous = []

    def attempt_ambiguous(sess_holder, staged, delay_s, plan):
        """Stage rows, send commit over a raw socket, SIGKILL the server before
        the client consumes any response. Restart and establish ground truth.
        Returns the new session."""
        sess = sess_holder[0]
        tx = sess.begin()
        t_stage = ev.mono_ms()
        for r in staged:
            sess.put(tx, r)
        t_staged = ev.mono_ms()
        req = (
            f"POST /v1/lamina/transactions/{tx}/commit HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{sess.port}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ).encode()
        sock = socket.create_connection(("127.0.0.1", sess.port))
        t_send = ev.mono_ms()
        sock.sendall(req)
        time.sleep(delay_s)
        sess.kill()
        t_kill = ev.mono_ms()
        remnant = b""
        try:
            sock.settimeout(1.0)
            remnant = sock.recv(65536)
        except (ConnectionResetError, socket.timeout, OSError):
            remnant = b""
        sock.close()
        outcome = {
            "plan": plan,
            "staged_samples": [r["sample"] for r in staged] if len(staged) <= 4 else f"{staged[0]['sample']}..{staged[-1]['sample']}",
            "staged_count": len(staged),
            "tx": tx,
            "delay_ms": delay_s * 1000.0,
            "t_stage_ms": t_stage,
            "t_staged_ms": t_staged,
            "t_send_ms": t_send,
            "t_kill_ms": t_kill,
            "response_consumed_before_crash": False,
            "response_bytes_observed_after_kill": len(remnant),
            "response_remnant_prefix": remnant[:120].decode(errors="replace"),
        }
        if remnant:
            safe = "".join(c if c.isalnum() else "-" for c in plan)
            outcome["remnant_excerpt"] = ev.save_excerpt(
                f"ambiguous-remnant-{safe}",
                remnant.decode(errors="replace") + "\n",
                f"response bytes still in flight after SIGKILL for plan {plan}; not consumed by the client before the crash",
            )
        ev.event(sess.name, "ambiguous-commit-crash", **outcome)
        # restart on the same data dir and establish the truth independently
        sess2 = Session(ev, binary, dir_a, f"S1-r{len(ambiguous)+1}").start()
        stats = sess2.stats()
        current = {r["sample"] for r in sess2.rows()}
        present = sum(1 for r in staged if r["sample"] in current)
        outcome["post_restart"] = {
            "sequence": stats["sequence"],
            "recovered_tail_bytes": stats["recovered_tail_bytes"],
            "staged_count": len(staged),
            "present_count": present,
            "durable": present == len(staged),
            "atomic": present in (0, len(staged)),
        }
        ev.event(sess2.name, "ambiguous-commit-truth", plan=plan, **outcome["post_restart"])
        ambiguous.append(outcome)
        sess_holder[0] = sess2
        if present == len(staged):
            for r in staged:
                model[r["sample"]] = copy.deepcopy(r)
        elif present != 0:
            ev.event("driver", "ATOMICITY-VIOLATION", plan=plan, present=present, staged=len(staged))
        return sess2

    holder = [s1]
    # Plan A0: large commit (max write set), kill immediately. The validation +
    # marshal window is wide, so the kill reliably lands before the journal
    # write: unconfirmed AND (as observed) not durable.
    big = [row(5000 + i) for i in range(1000)]
    attempt_ambiguous(holder, big, 0.0, "A0:large-commit-kill-immediately")
    model_at[ambiguous[-1]["post_restart"]["sequence"]] = copy.deepcopy(model)

    # Plan A: single-row commit, kill immediately. Race between the commit path
    # and SIGKILL; retry only if a response was actually emitted before kill.
    retries = 0
    while True:
        key = 7 if retries == 0 else 700 + retries
        attempt_ambiguous(holder, [row(key)], 0.0, "A:small-commit-kill-immediately")
        out = ambiguous[-1]
        if out["response_bytes_observed_after_kill"] == 0:
            break
        retries += 1
        if retries > 5:
            raise RuntimeError("could not obtain an unconfirmed plan-A attempt")
        ev.event("driver", "ambiguous-retry", reason="response emitted before kill; attempt reclassified as confirmed", key=key)
    model_at[ambiguous[-1]["post_restart"]["sequence"]] = copy.deepcopy(model)

    # Plan B: kill after 60ms -> commit almost certainly completed server-side,
    # but the client had not consumed the response at crash time.
    attempt_ambiguous(holder, [row(8)], 0.060, "B:kill-after-60ms-unconsumed-response")
    model_at[ambiguous[-1]["post_restart"]["sequence"]] = copy.deepcopy(model)
    cur = holder[0]

    ok, _ = check_rows(cur, "after-ambiguous-restarts", model)
    assert ok, "model mismatch after ambiguous restarts"

    # ------------------------------------------------- S3 checkpoint topology
    tx = cur.begin(); cur.put(tx, row(9))
    confirm(cur, tx, "row9", [row(9)])
    ckpt = cur.call("POST", "/checkpoint")
    ckpt_seq = ckpt["sequence"]
    ev.save_api("s3-checkpoint-response", ckpt)
    ev.event(cur.name, "checkpoint", sequence=ckpt_seq)

    tx = cur.begin(); cur.put(tx, row(10))
    head_h = confirm(cur, tx, "row10", [row(10)])

    cur.stop()
    s3 = Session(ev, binary, dir_a, "S3").start()
    stats_s3 = s3.stats()
    ev.save_api("s3-stats-after-checkpoint-restart", stats_s3)
    ok, rows_s3 = check_rows(s3, "checkpoint+journal-suffix", model)
    rows_at_ckpt = sorted_rows(s3.rows(at=ckpt_seq))
    want_at_ckpt = sorted_rows(model_at[ckpt_seq].values())
    ckpt_time_travel_ok = rows_at_ckpt == want_at_ckpt
    ev.event("S3", "time-travel-at-checkpoint", at=ckpt_seq, match=ckpt_time_travel_ok)

    j_a = parse_journal(dir_a / "journal.lmw")
    ev.save_journal_table("A-journal-after-S3", j_a)
    img_ckpt = parse_image_bytes((dir_a / "checkpoint.lmi").read_bytes())
    ev.event("S3", "checkpoint-image-decoded", sequence=img_ckpt["sequence"], digest_ok=img_ckpt["digest_ok"],
             rows=len(img_ckpt["rows_by_table"].get("spectra", [])))
    ev.hash_only(dir_a / "journal.lmw", "source journal after S3 (full content hash-only)")
    ev.hash_only(dir_a / "checkpoint.lmi", "checkpoint image at sequence %d" % ckpt_seq)

    # ------------------------------------------------- S4 backup and restore
    backup_bytes = s3.call("GET", "/backup", raw=True)
    backup_path = work / "backup-H.lmi"
    backup_path.write_bytes(backup_bytes)
    img_backup = parse_image_bytes(backup_bytes)
    backup_seq = img_backup["sequence"]
    ev.event("S3", "backup-captured", sequence=backup_seq, sha256=hashlib.sha256(backup_bytes).hexdigest(),
             bytes=len(backup_bytes), digest_ok=img_backup["digest_ok"])
    ev.hash_only(backup_path, "portable backup image (hash-only; envelope header retained in excerpts)")
    ev.save_excerpt("backup-envelope-head", hex_dump(backup_bytes[:160]) + "\n", "first 160 bytes of backup envelope")

    # post-backup source commit: must NOT appear in the restored instance
    tx = s3.begin(); s3.put(tx, row(11))
    seq_post_backup = confirm(s3, tx, "row11-post-backup", [row(11)])

    # source change feed evidence for the masking demo and lineage comparison
    changes_src_from_cursor = s3.call("GET", f"/changes?after={seq_cursor}&limit=1000")
    ev.save_api("s3-changes-after-cursor-source", changes_src_from_cursor)
    changes_src_from_base = s3.call("GET", f"/changes?after={backup_seq}&limit=1000")
    ev.save_api("s3-changes-after-backup-seq-source", changes_src_from_base)
    s3.stop()

    j_a_final = parse_journal(dir_a / "journal.lmw")
    ev.save_journal_table("A-journal-final", j_a_final)
    ev.hash_only(dir_a / "journal.lmw", "source journal final (hash-only)")
    ev.save_excerpt(
        "A-journal-header",
        hex_dump((dir_a / "journal.lmw").read_bytes()[:16]) + f"\nbase={j_a_final['base']} header_ok={j_a_final['header_ok']}\n",
        "source journal header (16 bytes)",
    )

    # restore into a fresh directory
    dir_r = work / "R-restored"
    s4 = Session(ev, binary, dir_r, "S4", restore=backup_path).start()
    stats_s4 = s4.stats()
    ev.save_api("s4-stats-restored", stats_s4)
    restored_model = copy.deepcopy(model_at[backup_seq])
    ok_r, rows_r = check_rows(s4, "restored==backup-image", restored_model)
    row11_absent = all(r["sample"] != 11 for r in rows_r)
    ev.event("S4", "post-backup-commit-absent", row11_absent=row11_absent)

    code_410, body_410 = s4.raw_call("GET", f"/changes?after={seq_cursor}")
    ev.save_api("s4-changes-old-cursor-410", {"status": code_410, "body": json.loads(body_410)})
    code_base, body_base = s4.raw_call("GET", f"/changes?after={backup_seq}")
    ev.save_api("s4-changes-at-base-200", {"status": code_base, "body": json.loads(body_base)})
    ev.event("S4", "old-cursor-rejected", cursor=seq_cursor, status=code_410, history_base=stats_s4["history_base"])

    # masking trap: current value equals consumer's last-seen value
    cur_row2 = next(r for r in rows_r if r["sample"] == 2)
    last_seen = model_at[seq_cursor][2]["amplitude"]
    ev.event("S4", "masking-trap-demonstrated",
             consumer_cursor=seq_cursor, consumer_last_seen_amplitude=last_seen,
             restored_current_amplitude=cur_row2["amplitude"],
             transitions_missed=[seq_up, seq_down],
             note="current value identical to last-seen value, yet committed transitions are unreachable (410)")

    # restored instance continues: same sequence number, different lineage
    tx = s4.begin(); s4.put(tx, row(12))
    out_r, t_s, t_r = s4.commit(tx)
    ev.event("S4", "restored-commit", sequence=out_r["sequence"], note="same sequence number as source's post-backup commit, different content")
    changes_r_from_base = s4.call("GET", f"/changes?after={backup_seq}&limit=1000")
    ev.save_api("s4-changes-after-base-restored", changes_r_from_base)
    src_rec = changes_src_from_base["records"][0] if changes_src_from_base["records"] else None
    r_rec = changes_r_from_base["records"][0] if changes_r_from_base["records"] else None
    lineage_diverges = (
        src_rec and r_rec
        and src_rec["sequence"] == r_rec["sequence"] == backup_seq + 1
        and src_rec.get("transaction") != r_rec.get("transaction")
    )
    ev.event("S4", "lineage-divergence", same_sequence=backup_seq + 1,
             source_transaction=src_rec.get("transaction") if src_rec else None,
             restored_transaction=r_rec.get("transaction") if r_rec else None,
             diverges=bool(lineage_diverges))

    s4.stop()
    s5 = Session(ev, binary, dir_r, "S5").start()
    stats_s5 = s5.stats()
    ev.save_api("s5-stats-restored-restart", stats_s5)
    restored_model[12] = row(12)
    ok_r2, _ = check_rows(s5, "restored+own-journal-after-restart", restored_model)
    j_r = parse_journal(dir_r / "journal.lmw")
    ev.save_journal_table("R-journal-after-S5", j_r)
    ev.save_excerpt(
        "R-journal-header",
        hex_dump((dir_r / "journal.lmw").read_bytes()[:16]) + f"\nbase={j_r['base']} header_ok={j_r['header_ok']}\n",
        "restored journal header: base equals backup sequence",
    )
    ev.hash_only(dir_r / "journal.lmw", "restored journal (hash-only)")
    ev.hash_only(dir_r / "checkpoint.lmi", "restored checkpoint image installed from backup (hash-only)")
    s5.stop()

    # ------------------------------------------------- S5 incomplete tail
    dir_tail = work / "A-tail"
    shutil.copytree(dir_a, dir_tail)
    jpath = dir_tail / "journal.lmw"
    before = jpath.read_bytes()
    with open(jpath, "ab") as f:
        f.write(b"\x00\x00\x00")
    after = jpath.read_bytes()
    ev.hash_data("A-tail-journal-with-3-byte-tail-before-restart", after,
                 "journal state with the appended incomplete tail, before recovery truncated it")
    ev.save_excerpt(
        "tail-append-before-after",
        "before (last 32 bytes):\n" + hex_dump(before[-32:], base=len(before) - 32)
        + "\n\nafter append of 3 bytes (last 35 bytes):\n" + hex_dump(after[-35:], base=len(after) - 35) + "\n",
        "incomplete tail injection: 3 trailing bytes appended to a copy of the source journal",
    )
    s6 = Session(ev, binary, dir_tail, "S6").start()
    stats_s6 = s6.stats()
    ev.save_api("s6-stats-tail-recovered", stats_s6)
    ok_t, _ = check_rows(s6, "tail-truncation", model)
    j_tail = parse_journal(dir_tail / "journal.lmw")
    ev.save_journal_table("A-tail-journal-after-truncation", j_tail)
    ev.hash_only(dir_tail / "journal.lmw", "journal after automatic tail truncation (hash-only)")
    s6.stop()

    # ------------------------------------------------- S6 corruption refusal
    corrupt_results = []
    for tag, offset_fn in (
        ("last-frame", lambda d: len(d) - 1),
        ("mid-frame", lambda d: 16 + 8 + 2),
    ):
        dirc = work / f"A-corrupt-{tag}"
        shutil.copytree(dir_a, dirc)
        jp = dirc / "journal.lmw"
        data = bytearray(jp.read_bytes())
        off = offset_fn(data)
        orig = data[off]
        data[off] ^= 0x01
        jp.write_bytes(data)
        flipped_hash = sha256_file(jp)
        ev.save_excerpt(
            f"corrupt-{tag}-flip",
            f"offset={off} original=0x{orig:02x} flipped=0x{data[off]:02x}\n"
            + hex_dump(bytes(data[max(0, off - 16) : off + 16]), base=max(0, off - 16)) + "\n",
            f"single-bit flip in {tag} of a journal copy",
        )
        try:
            proc = subprocess.run(
                [str(binary), "-data", str(dirc), "-listen", "127.0.0.1:0"],
                capture_output=True, text=True, timeout=15,
            )
            exit_code = proc.returncode
            stderr = proc.stderr
            timed_out = False
        except subprocess.TimeoutExpired as exc:
            exit_code = None
            stderr = (exc.stderr or b"").decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            timed_out = True
        stderr_tail = stderr.strip().splitlines()[-1] if stderr.strip() else ""
        unchanged = sha256_file(jp) == flipped_hash
        refused = not timed_out and exit_code != 0 and "checksum" in stderr
        corrupt_results.append({"specimen": tag, "refused": refused, "exit_code": exit_code,
                                "timed_out_still_serving": timed_out, "flipped_sha256": flipped_hash,
                                "stderr_tail": stderr_tail, "journal_unmodified_after_refusal": unchanged})
        ev.event("driver", f"corruption-{tag}", refused=refused, exit_code=exit_code,
                 timed_out_still_serving=timed_out, flipped_sha256=flipped_hash,
                 stderr_tail=stderr_tail, journal_unmodified_after_refusal=unchanged)
        ev.save_api(f"s6-corrupt-{tag}-startup", {"exit_code": exit_code, "timed_out_still_serving": timed_out,
                                                  "stderr_tail": stderr_tail,
                                                  "journal_unmodified_after_refusal": unchanged})
        ev.hash_only(jp, f"corrupted journal specimen {tag} (hash-only)")

    # ---------------------------------------------------------------- claims
    amb_summary = [
        {"plan": a["plan"], "staged": a["staged_count"], "durable": a["post_restart"]["durable"],
         "tail_bytes": a["post_restart"]["recovered_tail_bytes"],
         "response_bytes_after_kill": a["response_bytes_observed_after_kill"]}
        for a in ambiguous
    ]
    amb_ok = all(a["post_restart"]["atomic"] for a in ambiguous) and any(
        a["response_bytes_observed_after_kill"] == 0 for a in ambiguous
    )
    outcomes = {a["post_restart"]["durable"] for a in ambiguous}
    ev.claim(
        "C1-confirmed-prefix-durable",
        "Every commit the server confirmed with 200 + sequence is present after SIGKILL crash and restart; recovered rows equal the independent client-side model exactly.",
        "independent row model vs /query after restart; journal decode contiguity base+1..head",
        "verified" if ok else "refuted",
        ["api/s3-stats-after-checkpoint-restart.json", "journal-tables/A-journal-final.json", "events.jsonl"],
        f"confirmed commits: {[c['sequence'] for c in commit_log]}",
    )
    ev.claim(
        "C2-ambiguous-commit-indeterminate-at-crash",
        "A commit whose response was not consumed before the crash has no client-decidable outcome; ground truth is established only by recovery inspection. Both resolutions were run: a large commit killed before the journal write was LOST; small commits killed after the write/fsync were DURABLE despite the missing confirmation.",
        "raw-socket commit + SIGKILL at controlled delays and write-set sizes; post-restart /query + independent journal decode; all-or-nothing spot-check of the write set",
        "verified" if amb_ok else "refuted",
        ["events.jsonl", "journal-tables/A-journal-final.json"],
        json.dumps({"instances": amb_summary, "both_outcomes_observed": outcomes == {True, False}}, ensure_ascii=False),
    )
    topo1 = (
        img_ckpt["sequence"] == ckpt_seq
        and img_ckpt["digest_ok"]
        and j_a["base"] <= ckpt_seq
        and all(f.get("contiguous") for f in j_a["frames"])
        and j_a["frames"][-1]["sequence"] == head_h
        and stats_s3["sequence"] == head_h
        and ok and ckpt_time_travel_ok
    )
    ev.claim(
        "C3-checkpoint-plus-suffix-equals-prefix",
        f"Recovered state = checkpoint image [1..{ckpt_seq}] + journal suffix [{ckpt_seq+1}..{head_h}] = exactly the confirmed commit prefix [1..{head_h}]; no gap, no extra.",
        "independent image decode (digest, sequence) + independent journal frame table (contiguity) + row model at head and at checkpoint sequence",
        "verified" if topo1 else "refuted",
        ["journal-tables/A-journal-after-S3.json", "api/s3-checkpoint-response.json", "api/s3-stats-after-checkpoint-restart.json", "events.jsonl"],
        f"image.sequence={img_ckpt['sequence']}, journal frames {j_a['frames'][0]['sequence'] if j_a['frames'] else None}..{j_a['frames'][-1]['sequence'] if j_a['frames'] else None}, head={head_h}",
    )
    topo2 = (
        img_backup["digest_ok"] and img_backup["sequence"] == backup_seq
        and ok_r and row11_absent
        and j_r["base"] == backup_seq
        and len(j_r["frames"]) == 1 and j_r["frames"][0]["sequence"] == backup_seq + 1
        and ok_r2 and stats_s5["sequence"] == backup_seq + 1
    )
    ev.claim(
        "C4-backup-plus-catchup-equals-restored-prefix",
        f"Restored state = backup image [1..{backup_seq}] + restored-instance journal [{backup_seq+1}..{stats_s5['sequence']}]; the source's post-backup commit (seq {seq_post_backup}, row 11) is NOT part of the restored prefix.",
        "independent backup decode + restored journal header/base decode + row model comparison; post-backup row absence check",
        "verified" if topo2 else "refuted",
        ["api/s4-stats-restored.json", "api/s5-stats-restored-restart.json", "journal-tables/R-journal-after-S5.json", "excerpts/R-journal-header.txt", "events.jsonl"],
        f"backup.sequence={backup_seq}, restored journal base={j_r['base']}, restored head={stats_s5['sequence']}",
    )
    tail_ok = stats_s6["recovered_tail_bytes"] == 3 and ok_t and stats_s6["sequence"] == seq_post_backup
    ev.claim(
        "C5-incomplete-tail-truncated",
        "A 3-byte incomplete tail is truncated at startup; the committed prefix is unchanged (recovered_tail_bytes=3, head and rows identical to pre-append).",
        "append 3 bytes to a journal copy; restart; stats + row model + journal re-decode",
        "verified" if tail_ok else "refuted",
        ["api/s6-stats-tail-recovered.json", "excerpts/tail-append-before-after.txt", "journal-tables/A-tail-journal-after-truncation.json"],
        f"recovered_tail_bytes={stats_s6['recovered_tail_bytes']}",
    )
    corr_ok = all(c["refused"] and c["journal_unmodified_after_refusal"] for c in corrupt_results)
    ev.claim(
        "C6-complete-corruption-refused",
        "A single-bit flip inside a complete frame (last frame or middle frame) makes startup FAIL with a checksum error; the journal is not silently truncated or modified.",
        "byte flip on copies; run binary; check exit code, stderr, and file hash before/after",
        "verified" if corr_ok else "refuted",
        ["api/s6-corrupt-last-frame-startup.json", "api/s6-corrupt-mid-frame-startup.json",
         "excerpts/corrupt-last-frame-flip.txt", "excerpts/corrupt-mid-frame-flip.txt"],
        json.dumps(corrupt_results),
    )
    cursor_ok = code_410 == 410 and code_base == 200 and lineage_diverges
    ev.claim(
        "C7-cursor-gap-not-maskable",
        f"After restore, change cursors below history_base={backup_seq} are rejected (410), even though current row values can be identical to a consumer's last-seen values (row2 amplitude unchanged while transitions at seq {seq_up},{seq_down} are unreachable). Cursors at the base are accepted but continue on a DIFFERENT lineage: sequence {backup_seq+1} exists on both sides with different transaction ids/content.",
        "raw /changes calls on source and restored instances; transaction-id comparison at the same sequence number",
        "verified" if cursor_ok else "refuted",
        ["api/s4-changes-old-cursor-410.json", "api/s4-changes-at-base-200.json", "api/s3-changes-after-cursor-source.json",
         "api/s3-changes-after-backup-seq-source.json", "api/s4-changes-after-base-restored.json"],
        "410 for cursor<base; 200 for cursor==base with new-lineage records",
    )

    # ---------------------------------------------------------------- summary
    ev.event("driver", "run-complete")
    for logf in sorted(work.glob("*.stderr.log")):
        ev.hash_only(logf, "server stderr log (hash-only; startup logs are not the evidence, the decoded state is)")
    summary = {
        "environment": env_info,
        "work_dir_not_retained": str(work),
        "sequences": {
            "journal_base_source": j_a_final["base"],
            "journal_first_record_source": j_a_final["frames"][0]["sequence"] if j_a_final["frames"] else None,
            "confirmed_commits": [c["sequence"] for c in commit_log],
            "consumer_cursor": seq_cursor,
            "masking_transitions": [seq_up, seq_down],
            "checkpoint": ckpt_seq,
            "head_at_backup": backup_seq,
            "source_head_final": seq_post_backup,
            "restored_base": backup_seq,
            "restored_head": stats_s5["sequence"],
        },
        "ambiguous_commits": ambiguous,
        "verification": {
            "rows_after_ambiguous_restarts": ok,
            "time_travel_at_checkpoint": ckpt_time_travel_ok,
            "restored_equals_backup_image": ok_r,
            "post_backup_commit_absent_in_restored": row11_absent,
            "restored_after_restart": ok_r2,
            "tail_truncation": tail_ok,
            "corruption_refusals": corrupt_results,
            "cursor_gap": {"old_cursor_410": code_410 == 410, "at_base_200": code_base == 200,
                           "lineage_diverges_at_same_sequence": bool(lineage_diverges)},
        },
        "claims": {c["id"]: c["result"] for c in ev.claims},
        "run_end_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds"),
        "duration_ms": ev.mono_ms(),
    }
    ev._write_json("summary.json", summary)
    ev.manifest.append(ev._entry("summary.json", "raw", "run summary"))
    ev._write_json("claims.json", ev.claims)
    ev.manifest.append(ev._entry("claims.json", "raw", "claim-by-claim verification results"))
    ev._write_json("manifest.json", ev.manifest)

    retained = sum(m.get("bytes", 0) for m in ev.manifest if m.get("retention") in ("raw", "excerpt", "derived"))
    hash_only = sum(m.get("bytes", 0) for m in ev.manifest if m.get("retention") == "hash-only")
    print(json.dumps({
        "out": str(ev.out),
        "claims": summary["claims"],
        "retained_bytes": retained,
        "hash_only_bytes": hash_only,
        "duration_ms": summary["duration_ms"],
    }, indent=1))
    if any(c["result"] != "verified" for c in ev.claims):
        sys.exit(2)


if __name__ == "__main__":
    main()
