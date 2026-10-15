#!/usr/bin/env python3
"""Summarise netem-bench.sh runs as a Markdown table.

Usage: report.py OUT_DIR SHAPER
Each run directory holds meta.txt, iperf.json, ping-idle.txt, ping-load.txt and
the client's and server's stats endpoint snapshots.
"""

import json
import re
import statistics
import sys
from pathlib import Path


def rtts(path):
    try:
        text = path.read_text()
    except OSError:
        return []
    return [float(m) for m in re.findall(r"time=([\d.]+) ms", text)]


def pct(values, q):
    if not values:
        return None
    values = sorted(values)
    return values[min(len(values) - 1, int(q * len(values)))]


def ms(value):
    return "–" if value is None else f"{value:.0f}"


def iperf(path):
    try:
        data = json.loads(path.read_text())
        end = data["end"]
        return end["sum_received"]["bits_per_second"] / 1e6, end["sum_sent"].get("retransmits")
    except (OSError, ValueError, KeyError):
        return None, None


def drops(path):
    try:
        conns = json.loads(path.read_text())["connections"]
    except (OSError, ValueError, KeyError):
        return None, None
    return (
        sum(c.get("datagrams_dropped_delay", 0) for c in conns),
        sum(c.get("datagrams_dropped_overflow", 0) for c in conns),
    )


def main():
    out, shaper = Path(sys.argv[1]), sys.argv[2]
    rows = []
    for meta in sorted(out.glob("*/meta.txt")):
        d = meta.parent
        scen, var, direction, rate, delay, loss = meta.read_text().split()
        goodput, retrans = iperf(d / "iperf.json")
        idle, load = rtts(d / "ping-idle.txt"), rtts(d / "ping-load.txt")
        # The tunnel's sender for this direction holds the queue.
        sender = "server" if direction == "download" else "client"
        delay_drops, overflow_drops = drops(d / f"stats-{sender}.json")
        load_loss = None
        m = re.search(r"([\d.]+)% packet loss", (d / "ping-load.txt").read_text()
                      if (d / "ping-load.txt").exists() else "")
        if m:
            load_loss = float(m.group(1))
        rows.append(
            (
                f"{scen} ({rate} Mbit/s, {2 * int(delay)} ms RTT, {loss}% loss)",
                var,
                direction,
                "–" if goodput is None else f"{goodput:.1f}",
                "–" if retrans is None else str(retrans),
                ms(statistics.median(idle) if idle else None),
                ms(pct(load, 0.5)),
                ms(pct(load, 0.95)),
                "–" if load_loss is None else f"{load_loss:g}%",
                "–" if delay_drops is None else f"{delay_drops} / {overflow_drops}",
            )
        )

    print(f"## rapidmasque netem results ({shaper})\n")
    if shaper != "netem":
        print("Shaped with tbf: rate and buffer only, no delay or loss.\n")
    print(
        "TCP (iperf3) inside WireGuard (MTU 1280) inside the tunnel; a ping runs "
        "alongside the load. RTTs in ms. Drops: datagrams the tunnel's sender "
        "dropped for queueing delay / for a full send buffer.\n"
    )
    print(
        "| link | variant | direction | goodput Mbit/s | TCP retrans | idle RTT | "
        "loaded RTT p50 | p95 | ping loss | drops delay / overflow |"
    )
    print("|---|---|---|---|---|---|---|---|---|---|")
    for row in rows:
        print("| " + " | ".join(row) + " |")


if __name__ == "__main__":
    main()
