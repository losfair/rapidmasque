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


def median(values):
    values = [v for v in values if v is not None]
    return statistics.median(values) if values else None


def num(value, fmt="{:.0f}"):
    return "–" if value is None else fmt.format(value)


def measure(d):
    """Metrics of one run directory."""
    scen, var, direction, rate, delay, loss = (d / "meta.txt").read_text().split()
    goodput, retrans = iperf(d / "iperf.json")
    idle, load = rtts(d / "ping-idle.txt"), rtts(d / "ping-load.txt")
    # The tunnel's sender for this direction holds the queue.
    sender = "server" if direction == "download" else "client"
    delay_drops, overflow_drops = drops(d / f"stats-{sender}.json")
    load_loss = None
    if (d / "ping-load.txt").exists():
        m = re.search(r"([\d.]+)% packet loss", (d / "ping-load.txt").read_text())
        if m:
            load_loss = float(m.group(1))
    key = (scen, int(rate), int(delay), loss, var, direction)
    return key, {
        "goodput": goodput,
        "retrans": retrans,
        "idle": statistics.median(idle) if idle else None,
        "p50": pct(load, 0.5),
        "p95": pct(load, 0.95),
        "loss": load_loss,
        "delay_drops": delay_drops,
        "overflow_drops": overflow_drops,
    }


def main():
    out, shaper = Path(sys.argv[1]), sys.argv[2]
    cells = {}
    for meta in sorted(out.glob("*/meta.txt")):
        key, metrics = measure(meta.parent)
        cells.setdefault(key, []).append(metrics)

    print(f"## rapidmasque netem results ({shaper})\n")
    if shaper != "netem":
        print("Shaped with tbf: rate and buffer only, no delay or loss.\n")
    print(
        "TCP (iperf3) inside WireGuard (MTU 1280) inside the tunnel; a ping runs "
        "alongside the load. Each cell is the median over n runs. RTTs in ms. Drops: "
        "datagrams the tunnel's sender dropped for queueing delay / for a full send "
        "buffer.\n"
    )
    print(
        "| link | variant | direction | n | goodput Mbit/s | TCP retrans | idle RTT | "
        "loaded RTT p50 | p95 | ping loss | drops delay / overflow |"
    )
    print("|---|---|---|---|---|---|---|---|---|---|---|")
    for key in sorted(cells):
        scen, rate, delay, loss, var, direction = key
        runs = cells[key]
        m = {k: median([r[k] for r in runs]) for k in runs[0]}
        print(
            "| "
            + " | ".join(
                (
                    f"{scen} ({rate} Mbit/s, {2 * delay} ms RTT, {loss}% loss)",
                    var,
                    direction,
                    str(len(runs)),
                    num(m["goodput"], "{:.1f}"),
                    num(m["retrans"]),
                    num(m["idle"]),
                    num(m["p50"]),
                    num(m["p95"]),
                    num(m["loss"], "{:.1f}%"),
                    f"{num(m['delay_drops'])} / {num(m['overflow_drops'])}",
                )
            )
            + " |"
        )


if __name__ == "__main__":
    main()
