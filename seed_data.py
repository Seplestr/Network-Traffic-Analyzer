"""
seed_data.py  –  Populate the DB with realistic sample traffic logs.
Run:  python seed_data.py
"""
import random, requests
from datetime import datetime, timedelta

BASE = "http://127.0.0.1:8000/api/traffic"

PROTOCOLS  = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS"]
NORMAL_PORTS = [80, 443, 53, 8080, 8443, 3000, 5000]
SUSPICIOUS_PORTS = [22, 23, 3389, 4444, 445, 3306, 6379]
INTERNAL_IPS = [f"192.168.1.{i}" for i in range(10, 30)]
EXTERNAL_IPS = [f"203.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(10)]
EXTERNAL_IPS.append("10.0.0.99")   # known malicious IP


def random_log(suspicious=False):
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(EXTERNAL_IPS)
    if suspicious:
        dport = random.choice(SUSPICIOUS_PORTS)
        bytes_sent = random.randint(50_000_000, 200_000_000)  # big transfer
    else:
        dport = random.choice(NORMAL_PORTS)
        bytes_sent = random.randint(500, 2_000_000)

    return {
        "source_ip":   src,
        "dest_ip":     dst,
        "source_port": random.randint(1024, 65535),
        "dest_port":   dport,
        "protocol":    random.choice(PROTOCOLS),
        "bytes_sent":  float(bytes_sent),
        "bytes_recv":  float(random.randint(500, bytes_sent)),
        "duration_sec": round(random.uniform(0.1, 120.0), 2),
        "action":      "block" if suspicious and random.random() < 0.3 else "allow",
    }


def seed(n_normal=80, n_suspicious=20):
    logs = (
        [random_log(suspicious=False) for _ in range(n_normal)] +
        [random_log(suspicious=True)  for _ in range(n_suspicious)]
    )
    random.shuffle(logs)

    resp = requests.post(f"{BASE}/ingest/bulk", json={"logs": logs})
    if resp.status_code == 201:
        data = resp.json()
        flagged = sum(1 for r in data["results"] if r["flagged"])
        print(f"✅ Seeded {data['ingested']} logs — {flagged} flagged")
    else:
        print(f"❌ Error {resp.status_code}: {resp.text}")


if __name__ == "__main__":
    seed()
