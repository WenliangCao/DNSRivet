#!/usr/bin/env python3
"""Compare foreground DNSRivet binaries using loopback-only DNS traffic.

Example: python3 scripts/benchmark-local.py --binary before=PATH --binary after=PATH
No service commands, root access, public DNS queries, or third-party packages.
CPU includes daemon startup/shutdown; use enough queries to amortize those costs.
"""

import argparse
import asyncio
import contextlib
import json
import os
from pathlib import Path
import socket
import statistics
import struct
import subprocess
import tempfile
import time


QUERY = struct.pack("!6H", 0, 0x0100, 1, 0, 0, 0) + b"\x05bench\x07invalid\0\0\x01\0\x01"
ANSWER = (
    struct.pack("!6H", 0, 0x8180, 1, 1, 0, 0)
    + QUERY[12:]
    + b"\xc0\x0c\0\x01\0\x01"
    + struct.pack("!IH", 120, 4)
    + bytes([192, 0, 2, 1])
)


class Responder(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport
        self.queries = 0

    def datagram_received(self, packet, peer):
        if packet[2:] != QUERY[2:]:
            raise ValueError("unexpected benchmark query")
        self.queries += 1
        self.transport.sendto(packet[:2] + ANSWER[2:], peer)


class Client(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport
        self.pending = {}

    def datagram_received(self, packet, _peer):
        ident = int.from_bytes(packet[:2], "big")
        pending = self.pending.get(ident)
        if pending is not None and not pending.done():
            if len(packet) != len(ANSWER) or packet[2:8] != ANSWER[2:8] or packet[-4:] != ANSWER[-4:]:
                pending.set_exception(ValueError("unexpected benchmark answer"))
            else:
                pending.set_result(None)

    async def exchange(self, port, ident):
        pending = asyncio.get_running_loop().create_future()
        self.pending[ident] = pending
        started = time.perf_counter_ns()
        self.transport.sendto(ident.to_bytes(2, "big") + QUERY[2:], ("127.0.0.1", port))
        try:
            await pending
            return time.perf_counter_ns() - started
        finally:
            self.pending.pop(ident, None)


@contextlib.asynccontextmanager
async def daemon(binary, upstreams, cached, directory):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    args = [str(binary), "run", "--listen", f"127.0.0.1:{port}"]
    for upstream in upstreams:
        args += ["--upstream", f"legacy=127.0.0.1:{upstream}"]
    if not cached:
        args.append("--no-cache")
    log_path = directory / "daemon.log"
    result = {}
    with log_path.open("wb") as log:
        process = subprocess.Popen(args, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 5
            while b"listening on" not in log_path.read_bytes():
                if process.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError("benchmark daemon did not start: " + log_path.read_text())
                await asyncio.sleep(0.01)
            yield process.pid, port, result
        finally:
            if process.returncode is None:
                process.terminate()
                # wait4 accounts only this daemon, not the Python load generator.
                _, status, usage = await asyncio.to_thread(os.wait4, process.pid, 0)
                process.returncode = os.waitstatus_to_exitcode(status)
                result["cpu_seconds"] = usage.ru_utime + usage.ru_stime
                result["peak_rss_kib"] = usage.ru_maxrss / 1024 if os.uname().sysname == "Darwin" else usage.ru_maxrss


async def run_case(binary, mode, concurrency, queries, responder, client, directory):
    upstream = responder.transport.get_extra_info("sockname")[1]
    # The second responder shares the same endpoint; a healthy primary must
    # receive exactly one forwarded copy, never speculative background traffic.
    upstreams = [upstream] * (2 if mode == "legacy2" else 1)
    cached = mode in ("cached", "tcp-cached")
    before = responder.queries
    async with daemon(binary, upstreams, cached, directory) as (pid, port, metrics):
        await asyncio.wait_for(client.exchange(port, 0), 5)
        async def load(worker):
            samples = []
            if mode == "tcp-cached":
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                packet = (worker + 1).to_bytes(2, "big") + QUERY[2:]
                framed = len(packet).to_bytes(2, "big") + packet
                try:
                    for _ in range(worker, queries, concurrency):
                        started = time.perf_counter_ns()
                        writer.write(framed)
                        await writer.drain()
                        size = int.from_bytes(await reader.readexactly(2), "big")
                        response = await reader.readexactly(size)
                        assert response[:2] == packet[:2] and response[-4:] == ANSWER[-4:]
                        samples.append(time.perf_counter_ns() - started)
                finally:
                    writer.close()
                    await writer.wait_closed()
            else:
                for _ in range(worker, queries, concurrency):
                    samples.append(await client.exchange(port, worker + 1))
            return samples
        started = time.perf_counter_ns()
        batches = await asyncio.wait_for(
            asyncio.gather(*(load(worker) for worker in range(concurrency))), 120
        )
        elapsed = time.perf_counter_ns() - started
        rss = int(subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)], text=True))
    expected = 1 if cached else queries + 1
    assert responder.queries - before == expected, "unexpected upstream query count"
    samples = sorted(value for batch in batches for value in batch)
    return {
        "qps": round(queries * 1e9 / elapsed),
        "p50_us": round(statistics.median(samples) / 1000, 2),
        "p95_us": round(samples[int(len(samples) * 0.95)] / 1000, 2),
        "cpu_us_per_query": round(metrics["cpu_seconds"] * 1e6 / queries, 3),
        "rss_kib": rss,
        "peak_rss_kib": round(metrics["peak_rss_kib"]),
    }


async def benchmark(args):
    binaries = []
    for item in args.binary:
        label, separator, path = item.partition("=")
        if not separator:
            path, label = item, Path(item).name
        binary = Path(path).resolve(strict=True)
        binaries.append((label, binary))
    loop = asyncio.get_running_loop()
    server_transport, responder = await loop.create_datagram_endpoint(Responder, local_addr=("127.0.0.1", 0))
    client_transport, client = await loop.create_datagram_endpoint(Client, local_addr=("127.0.0.1", 0))
    rows = []
    try:
        with tempfile.TemporaryDirectory(prefix="dnsrivet-bench-") as temporary:
            for mode in args.mode:
                for concurrency in args.concurrency:
                    for sample in range(args.samples):
                        # Alternate order to reduce drift from warmup and thermal effects.
                        ordered = binaries if sample % 2 == 0 else list(reversed(binaries))
                        for label, binary in ordered:
                            values = await run_case(binary, mode, concurrency, args.queries, responder, client, Path(temporary))
                            row = {"binary": label, "mode": mode, "concurrency": concurrency, "sample": sample + 1, **values}
                            rows.append(row)
                            print(json.dumps(row), flush=True)
    finally:
        client_transport.close()
        server_transport.close()
    if args.json:
        Path(args.json).write_text(json.dumps(rows, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", action="append", required=True, help="LABEL=PATH; repeat to compare")
    parser.add_argument("--mode", nargs="+", choices=["cached", "tcp-cached", "legacy1", "legacy2"], default=["cached", "legacy1", "legacy2"])
    parser.add_argument("--concurrency", nargs="+", type=int, default=[1, 32])
    parser.add_argument("--queries", type=int, default=20000)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--json", help="also save measurements to this file")
    args = parser.parse_args()
    if args.queries < 1 or args.samples < 1 or any(not 1 <= n <= 128 for n in args.concurrency):
        parser.error("positive query/sample counts and concurrency between 1 and 128 are required")
    asyncio.run(benchmark(args))


if __name__ == "__main__":
    main()
