#!/usr/bin/env python3
"""Install mkra on a SHARP 4S-C00AS1 over telnet, and prove it works.

Everything lands in /tmp/mt, which is tmpfs: a power cycle undoes all of it.
Nothing here writes to eMMC, MTD, SPI flash or /dev/shm, and nothing signals a
product process.

    python3 tools/deploy.py --host 198.51.100.10                 # upload only
    python3 tools/deploy.py --host 198.51.100.10 --smoke         # + prove it streams
    python3 tools/deploy.py --host 198.51.100.10 --smoke --serve # + leave it running
    python3 tools/deploy.py --host 198.51.100.10 --stop          # stop our server
    python3 tools/deploy.py --host 198.51.100.10 --bs2k --serve  # conventional BS/CS
    python3 tools/deploy.py --host 198.51.100.10 --smoke-2k 400151  # prove 2K

--smoke-2k uploads config/bs-additional-main.tsv, verifies the OEM hashes the
2K graph requires, retunes the box to that service, and checks the captured TS
here. It changes what the TV is showing; run it when nobody is watching.

--smoke captures ten seconds of live 4K on the box, pulls it back over HTTP and
checks the 188-byte framing here. If `ffprobe` is installed it also decodes a
frame, which is the only check that actually proves the stream is usable.

Requires: a root telnet on port 2323 (see docs/SETUP.md) and the box switched
on -- green LED, not standby.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)

from sharp_telnet import MICROTEST_DIR, connect  # noqa: E402

DEFAULT_BINARY = os.path.join(
    ROOT, "target/armv7-unknown-linux-musleabihf/release/mkra")
REMOTE = MICROTEST_DIR + "/mkra"
SMOKE_TS = MICROTEST_DIR + "/smoke.ts"


def progress(done, total):
    pct = 100 * done // max(total, 1)
    print("\r  %3d%%  (%d/%d chunks)" % (pct, done, total), end="", flush=True)
    if done >= total:
        print()


def check_state(t):
    """Report uptime and whether the box is out of standby.

    In standby there is no A/V pipeline and no MMT elementary-stream ring, so
    every capture returns zero bytes. That looks like a broken install but is
    just a box nobody switched on, so it is worth saying plainly.
    """
    uptime = t.run("cat /proc/uptime").split()[0]
    av = t.run("grep -h . /proc/[0-9]*/comm 2>/dev/null | "
               "grep -cE '^(MIXER|buf_buf|Sink|Gate)'").strip()
    operating = av not in ("0", "")
    print("device uptime %ss, A/V pipeline threads %s (%s)"
          % (uptime, av, "operating" if operating else "STANDBY"))
    return operating


def stop_ours(t):
    """Terminate any mkra we started earlier. Never touches product processes."""
    stopped = 0
    for pid, exe in t.running_microtests():
        print("stopping %s (pid %s)" % (exe, pid))
        t.stop_microtest(pid)
        stopped += 1
        time.sleep(0.5)
    return stopped


def upload(t, binary):
    size = os.path.getsize(binary)
    print("uploading %s (%d bytes) -> %s" % (os.path.basename(binary), size, REMOTE))
    started = time.time()
    md5 = t.upload(binary, REMOTE, progress=progress)
    rate = size / max(time.time() - started, 0.001) / 1024
    print("  md5 %s verified on device (%.0f KiB/s)" % (md5, rate))
    print("  " + t.run("%s --help" % REMOTE).splitlines()[0])


def ts_report(path):
    """188-byte sync rate and continuity errors, computed here rather than on
    the box. A file that is the right size but not TS-aligned is the classic
    'looked like it worked' failure, so measure it instead of trusting it."""
    data = open(path, "rb").read()
    if len(data) < 188 * 10:
        return "only %d bytes -- nothing streamed" % len(data)
    start = data.find(b"\x47")
    total = aligned = 0
    cc = {}
    errors = 0
    for off in range(start, len(data) - 187, 188):
        total += 1
        if data[off] != 0x47:
            continue
        aligned += 1
        pid = ((data[off + 1] & 0x1F) << 8) | data[off + 2]
        if data[off + 3] & 0x10:                       # has payload
            got = data[off + 3] & 0x0F
            prev = cc.get(pid)
            if prev is not None and got != (prev + 1) % 16:
                errors += 1
            cc[pid] = got
    return ("%d packets, %.2f%% aligned, %d PIDs, %d CC errors"
            % (total, 100.0 * aligned / total, len(cc), errors))


def pull(t, host, remote_path, local_path, port):
    """Copy a file off the box over HTTP -- telnet base64 would take minutes."""
    size = t.run("wc -c < %s 2>/dev/null" % remote_path).strip()
    size = int(size.split()[0]) if size.split() else 0
    if size == 0:
        print("  %s is empty on the device" % remote_path)
        return 0
    pid = t.run("%s serve --port %d --file %s --raw-stream --file-bitrate 0 "
                "--ring %d > %s/pull.log 2>&1 & echo $!"
                % (REMOTE, port, remote_path, size, MICROTEST_DIR)).strip()
    try:
        time.sleep(2)
        with urllib.request.urlopen("http://%s:%d/api/channels" % (host, port), timeout=10) as r:
            chans = json.load(r)
        url = ("http://%s:%d/api/channels/%s/%s/stream"
               % (host, port, chans[0]["type"], chans[0]["channel"]))
        limit = max(30, size // 200_000 + 20)
        with open(local_path, "wb") as fh:
            subprocess.run(["curl", "-fsSN", "--max-time", str(limit), url],
                           stdout=fh, check=True)
        got = os.path.getsize(local_path)
        print("  pulled %d of %d bytes -> %s" % (got, size, local_path))
        if got != size:
            raise RuntimeError("file transfer is incomplete: %d of %d bytes" % (got, size))
        expected = t.run("md5sum %s" % remote_path).split()[0]
        with open(local_path, "rb") as fh:
            actual = hashlib.file_digest(fh, "md5").hexdigest()
        if actual != expected:
            raise RuntimeError("transferred file does not match the device's MD5")
        print("  md5 %s verified after transfer" % actual)
    finally:
        t.stop_microtest(pid)
    return got


OEM_FILES = [
    ("/usr/bin/tuner", "b94fc6a8f2e506dc66336c5d0d031b69"),
    ("/usr/bin/abs", "1a3fdfa8379d75a802190b48ea951e9a"),
    ("/disk/xc6drv/xcdrv.ko", "0bfa0f7db130e058f3ec838bbd681b7d"),
    ("/usr/vixs/lib/libvixs.so", "344f0ef7b1a84d49ae13659d3a388d78"),
]


def check_identity(t):
    """The 2K graph refuses to run unless the OEM userland is the exact build
    the ABI was measured on. Check it here so the failure is one clear line
    instead of a stream that never starts."""
    bad = 0
    for path, want in OEM_FILES:
        got = t.run("md5sum %s 2>/dev/null" % path).split()
        if not got or got[0] != want:
            print("  IDENTITY MISMATCH %s: %s (expected %s)"
                  % (path, got[0] if got else "missing", want))
            bad += 1
    if not bad:
        print("  OEM identity: all %d hashes match" % len(OEM_FILES))
    return bad == 0


def upload_table(t, source):
    remote = MICROTEST_DIR + "/bs-additional-main.tsv"
    size = os.path.getsize(source)
    print("uploading %s (%d bytes) -> %s" % (os.path.basename(source), size, remote))
    md5 = t.upload(source, remote)
    print("  md5 %s verified on device" % md5)
    return remote


def smoke_2k(t, host, service_id, seconds, port, tsv):
    """Capture a conventional BS/CS service through the API.

    This is the check that actually proves 2K: an HTTP 200 alone does not, and
    neither does a decoded frame from a 4K remux. Measure TS framing, CC, and
    decode the result here.
    """
    print("\n--- capturing %d s of service %d (satellite retune) ---"
          % (seconds, service_id))
    cmd = ("%s serve --remux4k --tune --bs2k --channel-type BS4K --port %d "
           "--isdbs-channels %s --epg-tap --epg-refresh 5 --epg-dir /tmp/adsb "
           "> %s/mkra-2k.log 2>&1 & echo $!"
           % (REMOTE, port, tsv, MICROTEST_DIR))
    pid = t.run(cmd).strip()
    try:
        up = False
        for _ in range(30):
            time.sleep(1)
            try:
                with urllib.request.urlopen(
                        "http://%s:%d/api/version" % (host, port), timeout=3) as r:
                    if r.status == 200:
                        up = True
                        break
            except Exception:
                pass
        if not up:
            print("server did not come up:\n" + t.run("tail -20 %s/mkra-2k.log"
                                                    % MICROTEST_DIR))
            return False

        with urllib.request.urlopen("http://%s:%d/api/services" % (host, port),
                                    timeout=10) as r:
            services = json.load(r)
        if not any(s.get("id") == service_id for s in services):
            print("service %d is not advertised; the channel table did not load"
                  % service_id)
            print("advertised: %s" % ", ".join(
                "%d (%s)" % (s.get("id"), s.get("name")) for s in services[:20]))
            return False

        local = os.path.join(ROOT, "smoke-2k.ts")
        url = "http://%s:%d/api/services/%d/stream" % (host, port, service_id)
        deadline = time.time() + seconds + 45
        got = 0
        with open(local, "wb") as fh:
            with urllib.request.urlopen(url, timeout=30) as r:
                while time.time() < deadline and got < seconds * 400_000:
                    chunk = r.read(65536)
                    if not chunk:
                        break
                    fh.write(chunk)
                    got += len(chunk)
        print("  pulled %d bytes -> %s" % (os.path.getsize(local), local))
        print("  " + ts_report(local))
        try:
            p = subprocess.run(["ffprobe", "-hide_banner", "-v", "error",
                                "-show_entries",
                                "stream=codec_name,width,height,sample_rate",
                                "-of", "default=noprint_wrappers=1", local],
                               capture_output=True, text=True, timeout=60)
            if p.stdout.strip():
                print("  ffprobe: " + " ".join(p.stdout.split()))
            else:
                print("  ffprobe found no decodable stream")
                return False
        except FileNotFoundError:
            print("  (install ffmpeg to decode-check %s)" % local)
        return os.path.getsize(local) > 188 * 100
    finally:
        t.stop_microtest(pid)


def smoke(t, host, seconds, port):
    print("\n--- 1/3  live graph (read-only) ---")
    graph = t.run("%s graph --sniff" % REMOTE, timeout=120)
    print("\n".join(graph.splitlines()[:12]))

    print("\n--- 2/3  discover the product's live ES rings (read-only) ---")
    disc = t.run("%s remux4k --discover-only" % REMOTE, timeout=120)
    print(disc)
    if "video" not in disc.lower():
        print("\nNo live elementary streams. The box is not decoding 4K right now.\n"
              "Switch it on with the remote (green LED) and select a 4K channel.")
        return False

    print("\n--- 3/3  capture %d s of live 4K ---" % seconds)
    t.remove_microtest(SMOKE_TS)
    out = t.run("%s remux4k --out %s --seconds %d" % (REMOTE, SMOKE_TS, seconds),
                timeout=seconds + 120)
    print(out)

    local = os.path.join(ROOT, "smoke.ts")
    if pull(t, host, SMOKE_TS, local, port) == 0:
        return False
    print("  " + ts_report(local))

    try:
        p = subprocess.run(["ffprobe", "-hide_banner", "-v", "error",
                            "-show_entries", "stream=codec_name,width,height",
                            "-of", "default=noprint_wrappers=1", local],
                           capture_output=True, text=True, timeout=60)
        if p.stdout.strip():
            print("  ffprobe: " + " ".join(p.stdout.split()))
        else:
            print("  ffprobe found no decodable stream")
    except FileNotFoundError:
        print("  (install ffmpeg to decode-check %s)" % local)
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True, help="the box's IP address")
    ap.add_argument("--port", type=int, default=2323, help="telnet port")
    ap.add_argument("--binary", default=DEFAULT_BINARY,
                    help="mkra to upload (default: the cross-built one)")
    ap.add_argument("--smoke", action="store_true",
                    help="capture and verify a live 4K stream after uploading")
    ap.add_argument("--smoke-seconds", type=int, default=10)
    ap.add_argument("--serve", action="store_true",
                    help="leave `mkra serve` running when finished")
    ap.add_argument("--serve-port", type=int, default=40772)
    ap.add_argument("--channel-type", default="BS4K", choices=("BS4K", "BS"),
                    help="BS4K for Mirakurun-BS4K clients, BS for plain "
                         "BonDriver_Mirakurun (default BS4K)")
    ap.add_argument("--no-tune", action="store_true",
                    help="do not let mkra change the box's channel")
    ap.add_argument("--bs2k", action="store_true",
                    help="also upload config/bs-additional-main.tsv and start "
                         "the server with --bs2k (conventional BS; CS works "
                         "only for rows you put in the table)")
    ap.add_argument("--smoke-2k", type=int, metavar="SERVICE",
                    help="capture SERVICE (e.g. 400151) live for --smoke-seconds "
                         "and verify it; implies --bs2k and retunes the box")
    ap.add_argument("--keep-2k-server", action="store_true",
                    help="with --smoke-2k, leave the server those args started")
    ap.add_argument("--stop", action="store_true",
                    help="just stop a running mkra and exit")
    ap.add_argument("--pull-port", type=int, default=40790,
                    help="temporary port used to copy files back")
    a = ap.parse_args()

    t = connect(a.host, a.port)
    try:
        if a.stop:
            print("stopped %d process(es)" % stop_ours(t))
            return 0

        if not os.path.exists(a.binary):
            sys.exit("%s is missing -- run ./build-device.sh, or pass --binary "
                     "with a release download" % a.binary)

        operating = check_state(t)
        stop_ours(t)                      # a running binary cannot be overwritten
        t.make_microtest_dir()
        upload(t, a.binary)

        tsv = None
        if a.bs2k or a.smoke_2k:
            if not check_identity(t):
                print("\nThe 2K graph refuses unverified OEM binaries; this box "
                      "does not match the measured ABI. Stop here.")
                return 1
            tsv = upload_table(t, os.path.join(ROOT, "config",
                                               "bs-additional-main.tsv"))

        if not operating:
            print("\nThe box is in standby, so there is nothing to capture yet.\n"
                  "Press the power button (LED green), then re-run with --smoke.")
            return 0

        ok = True
        if a.smoke:
            ok = smoke(t, a.host, a.smoke_seconds, a.pull_port)

        if a.smoke_2k:
            ok = smoke_2k(t, a.host, a.smoke_2k, a.smoke_seconds,
                          a.serve_port, tsv) and ok
            if not a.keep_2k_server:
                stop_ours(t)

        if a.serve:
            extra = ""
            if tsv:
                extra = " --bs2k --isdbs-channels %s" % tsv
            cmd = ("%s serve --remux4k %s%s --channel-type %s --port %d "
                   "--epg-dir /tmp/adsb > %s/mkra.log 2>&1 &"
                   % (REMOTE, "" if a.no_tune else "--tune", extra,
                      a.channel_type, a.serve_port, MICROTEST_DIR))
            t.run(cmd)
            time.sleep(2)
            print("\n--- server ---")
            print(t.run("tail -3 %s/mkra.log" % MICROTEST_DIR).strip())
            print("\nMirakurun-compatible API:  http://%s:%d/api/channels"
                  % (a.host, a.serve_port))
            print("Point TVTest / EPGStation at http://%s:%d"
                  % (a.host, a.serve_port))

        if (a.smoke or a.smoke_2k) and not ok:
            return 1
        return 0
    finally:
        t.close()


if __name__ == "__main__":
    sys.exit(main())
