#!/usr/bin/env python3
"""Score new flows with a trained hybrid model.

  python predict.py --model results-live/model.joblib --input flows.csv --output alerts.csv

Input CSV must contain the same feature columns used in training. Output adds
`alert` (0/1), `score`, and `reason` (known-attack / novel-anomaly / benign).
"""
import argparse

import joblib
import pandas as pd

ap = argparse.ArgumentParser()
ap.add_argument("--model", default="results-live/model.joblib")
ap.add_argument("--input", required=True)
ap.add_argument("--output", default="alerts.csv")
a = ap.parse_args()

bundle = joblib.load(a.model)
det, cols = bundle["detector"], bundle["columns"]
df = pd.read_csv(a.input)
X = df[cols]
flag, score = det.decision(X)
out = df.copy()
out["alert"], out["score"], out["reason"] = flag.astype(int), score, det.explain(X)
out.to_csv(a.output, index=False)
print(f"{flag.sum()} / {len(df)} flows flagged -> {a.output}")
print(out["reason"].value_counts().to_string())
