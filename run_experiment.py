#!/usr/bin/env python3
"""Run the full experiment suite.


Examples
--------
  python run_experiment.py --dataset synthetic --n-samples 40000
  python run_experiment.py --dataset cicids2017 --data-path ./data/MachineLearningCVE
  python run_experiment.py --dataset unsw-nb15  --data-path ./data/UNSW-NB15
"""
import argparse
import warnings

from cloudids.data import load_dataset
from cloudids.experiments import run_all

warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--dataset", default="synthetic", choices=["synthetic", "cicids2017", "unsw-nb15"])
    ap.add_argument("--data-path", default=None, help="CSV file or directory for real datasets")
    ap.add_argument("--n-samples", type=int, default=40000, help="rows for the synthetic generator")
    ap.add_argument("--cap-per-class", type=int, default=40000,
                    help="max rows per class when loading real datasets (memory control)")
    ap.add_argument("--holdouts", default="all",
                    help="comma-separated attack classes for the zero-day test, or 'all'")
    ap.add_argument("--ae-percentile", type=float, default=None,
                    help="legacy alias for combined target FPR (100 - percentile)")
    ap.add_argument("--target-fpr", type=float, default=None,
                    help="target combined Hybrid-OR false-positive rate on benign validation data")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default="results")
    ap.add_argument("--fast", action="store_true", help="smaller models / fewer epochs")
    ap.add_argument("--skip-zero-day", action="store_true")
    a = ap.parse_args()

    if a.target_fpr is not None and a.ae_percentile is not None:
        ap.error("use only one of --target-fpr and --ae-percentile")
    target_fpr = a.target_fpr
    if target_fpr is None:
        target_fpr = (1 - a.ae_percentile / 100) if a.ae_percentile is not None else 0.01
    if not 0 < target_fpr < 1:
        ap.error("the combined target FPR must be between 0 and 1")
    ds = load_dataset(a.dataset, a.data_path, a.n_samples, a.cap_per_class, a.seed)
    run_all(ds, a.out, a.seed, a.holdouts, a.fast, a.skip_zero_day,
            target_fpr=target_fpr)


if __name__ == "__main__":
    main()
