#!/usr/bin/env python3
"""
Normal DNS Traffic Generator
=============================
Sends realistic, benign DNS queries — the "control group" for your demo.
Side-by-side with tunnel_attacker.py, this should produce a clean threat
score while the tunnel script lights up the detector.

What "normal" looks like:
  - Real domains people actually visit
  - Mostly short labels (www, mail, api...) — low entropy
  - Low to moderate query rate per source
  - Diverse parent domains (no single domain dominates)
  - Mix of A/AAAA with occasional MX/TXT
"""

import argparse
import random
import socket
import struct
import sys
import time


# A pool of real, common domains. Diverse TLDs and lengths so the entropy
# distribution looks like a real user's browser + apps.
COMMON_DOMAINS = [
    "google.com", "youtube.com", "wikipedia.org", "github.com", "stackoverflow.com",
    "reddit.com", "amazon.com", "cloudflare.com", "microsoft.com", "apple.com",
    "nytimes.com", "bbc.co.uk", "weather.com", "espn.com", "linkedin.com",
    "duckduckgo.com", "mozilla.org", "python.org", "rust-lang.org", "kernel.org",
    "ubuntu.com", "debian.org", "archlinux.org", "openstreetmap.org", "wikimedia.org",
    "npmjs.com", "pypi.org", "docker.com", "kubernetes.io", "postgresql.org",
    "spotify.com", "netflix.com", "twitch.tv", "discord.com", "slack.com",
    "office.com", "icloud.com", "dropbox.com", "atlassian.com", "notion.so",
]

# Common subdomain prefixes — short, predictable, low entropy.
COMMON_PREFIXES = [
    "www", "mail", "api", "cdn", "static", "img", "images", "assets",
    "blog", "shop", "store", "docs", "help", "support", "login", "auth",
    "m", "mobile", "app", "ws", "ws1", "edge", "gateway", "ns1", "ns2",
]

QTYPES = [
    (1, 70),    # A — most common
    (28, 20),   # AAAA
    (15, 5),    # MX
    (16, 3),    # TXT
    (2, 2),     # NS
]


def build_dns_query(qname: str, qtype: int = 1) -> bytes:
    qid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname_wire = b""
    for label in qname.rstrip(".").split("."):
        b = label.encode("ascii")
        qname_wire += bytes([len(b)]) + b
    qname_wire += b"\x00"
    return header + qname_wire + struct.pack(">HH", qtype, 1)


def pick_qtype() -> int:
    types, weights = zip(*QTYPES)
    return random.choices(types, weights=weights, k=1)[0]


def pick_qname() -> str:
    domain = random.choice(COMMON_DOMAINS)
    # Most queries hit a subdomain; some hit the apex.
    r = random.random()
    if r < 0.55:
        return f"{random.choice(COMMON_PREFIXES)}.{domain}"
    elif r < 0.75:
        # Two-level: e.g. cdn.assets.github.com — still low entropy
        return f"{random.choice(COMMON_PREFIXES)}.{random.choice(COMMON_PREFIXES)}.{domain}"
    else:
        return domain


def send_udp(qname: str, qtype: int, resolver_ip: str, port: int = 53, timeout: float = 2.0):
    pkt = build_dns_query(qname, qtype)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(pkt, (resolver_ip, port))
        try:
            sock.recvfrom(4096)
        except socket.timeout:
            pass
    finally:
        sock.close()


def send_doh(qname: str, qtype: int, doh_url: str, timeout: float = 5.0):
    try:
        import requests
    except ImportError:
        print("DoH mode requires 'requests': pip install requests", file=sys.stderr)
        sys.exit(1)
    pkt = build_dns_query(qname, qtype)
    headers = {"content-type": "application/dns-message", "accept": "application/dns-message"}
    requests.post(doh_url, data=pkt, headers=headers, timeout=timeout)


def run(args):
    end_time = time.time() + args.duration if args.duration > 0 else float("inf")

    print(f"[*] Normal traffic generator starting")
    print(f"    target:    {args.target} ({'DoH' if args.doh else 'UDP/53'})")
    print(f"    rate:      ~{args.rate} qps (with jitter)")
    print(f"    duration:  {'unlimited' if args.duration <= 0 else f'{args.duration}s'}")
    print(f"[*] Ctrl+C to stop\n")

    sent = 0
    start = time.time()
    try:
        while time.time() < end_time:
            qname = pick_qname()
            qtype = pick_qtype()
            try:
                if args.doh:
                    send_doh(qname, qtype, args.target)
                else:
                    send_udp(qname, qtype, args.target)
                sent += 1
                if sent % 10 == 0 or args.verbose:
                    elapsed = time.time() - start
                    print(f"[+] sent={sent} elapsed={elapsed:.1f}s last={qname} (qtype={qtype})")
            except Exception as e:
                if args.verbose:
                    print(f"[!] error: {e}", file=sys.stderr)
            # Jittered interval — real traffic isn't perfectly periodic
            base = 1.0 / max(args.rate, 0.1)
            time.sleep(base * random.uniform(0.4, 1.8))
    except KeyboardInterrupt:
        print("\n[*] interrupted")
    finally:
        elapsed = time.time() - start
        print(f"\n[*] done: {sent} queries in {elapsed:.1f}s ({sent/max(elapsed,0.001):.1f} qps)")


def main():
    p = argparse.ArgumentParser(description="Generate benign DNS traffic for baseline comparison.")
    p.add_argument("--target", required=True,
                   help="Resolver IP (UDP) or full DoH URL")
    p.add_argument("--doh", action="store_true")
    p.add_argument("--rate", type=float, default=2.0,
                   help="Average qps (default: 2 — real users are slow)")
    p.add_argument("--duration", type=float, default=60.0,
                   help="Seconds to run; 0 = forever (default: 60)")
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()