#!/usr/bin/env python3
"""Send demo flows to a running CloudIDS server so the dashboard/alerts have data.

  python send_demo_flows.py --count 20
  python send_demo_flows.py --count 20 --src-ip 203.0.113.50   # also exercises blocking

Uses the token in CLOUDIDS_API_TOKEN. Values are RANDOM numbers that only
demonstrate the pipeline; they are not real traffic or a real security test.
"""
import argparse, json, os, random, uuid
from urllib.request import Request, urlopen

ap = argparse.ArgumentParser()
ap.add_argument("--base", default="http://127.0.0.1:8766")
ap.add_argument("--count", type=int, default=20)
ap.add_argument("--src-ip", default=None, help="attacker IP to attach (used by blocking)")
a = ap.parse_args()

headers = {"Authorization": f"Bearer {os.environ['CLOUDIDS_API_TOKEN']}",
           "Content-Type": "application/json"}
with urlopen(Request(f"{a.base}/v1/schema", headers=headers), timeout=5) as r:
    cols = json.load(r)["features"]

events = []
for i in range(a.count):
    scale = random.choice([1, 1, 1, 50, 5000])  # some wildly unusual flows
    event = {"event_id": f"demo-{uuid.uuid4().hex[:12]}", "source": "demo",
             "features": {c: abs(random.gauss(0, 1)) * scale for c in cols}}
    if a.src_ip:
        event["src_ip"] = a.src_ip
    events.append(event)

with urlopen(Request(f"{a.base}/v1/flows/batch", data=json.dumps({"events": events}).encode(),
                     headers=headers), timeout=30) as r:
    res = json.load(r)["results"]
print(f"sent {len(res)} flows, {sum(x['alert'] for x in res)} flagged")
for x in res[:5]:
    print(" ", x["event_id"], x["alert"], round(x["score"], 3), x["reason"], x["predicted_class"])
