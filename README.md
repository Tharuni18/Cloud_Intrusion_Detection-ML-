# CloudIDS: hybrid intrusion detection and live scoring

CloudIDS is a research/demo intrusion-detection pipeline with supervised known-attack
classification and benign-only anomaly detection. It can evaluate a labelled dataset,
save a model, and accept feature records through a small authenticated real-time API.

## Abstract features implemented

| Abstract capability | Implementation |
| --- | --- |
| Known attack prediction | Random Forest and XGBoost multi-class models |
| Unfamiliar/anomalous flow detection | Benign-only reconstruction autoencoder and MiniBatchKMeans distance detector |
| Combined prediction | Hybrid-OR: alert when any calibrated detector signals; includes signal reasons |
| Benchmark evaluation | Closed-world metrics, per-class recall, PR/ROC curves, latency and held-out-class experiments |
| Real-time scoring | Authenticated JSON API (`serve_realtime.py`) with one-flow and batch endpoints; results stored in SQLite |

The project predicts suspicious flow patterns. It does **not** prove that a breach occurred,
inspect packet payloads, or itself connect to an AWS/Azure/GCP account. A trusted collector
must extract the model's exact feature schema and send it to the API. The included UNSW-NB15
benchmark has no exfiltration ground-truth class; data theft alerts require storage, identity,
and audit events plus a model trained and evaluated on those signals.

## Quick start on Windows

The ZIP download includes the trained model bundle and dashboard. It excludes the large
training datasets and Python environment. Extract the ZIP, open the extracted
`CloudIDS-Project` folder in VS Code, then run this in PowerShell:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\start_cloudids.ps1
```

The launcher creates `.venv`, installs the model-compatible Python packages, generates a temporary API
token, starts the dashboard, and opens it at [http://127.0.0.1:8766](http://127.0.0.1:8766).
Keep the PowerShell window open while using the dashboard. Paste the token printed in that
window into the dashboard when prompted. The token is generated again each time the server
starts.

## Manual setup on Windows PowerShell

From the Downloads folder, enter the actual project directory:

```powershell
Set-Location "<path where you extracted or cloned the project>"
```

Then create or activate the project environment:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

The autoencoder uses scikit-learn by default. Install `torch` separately only if you want
the optional PyTorch autoencoder backend.

For a quick pipeline run with generated data:

```powershell
python run_experiment.py --dataset synthetic --n-samples 40000 --fast --skip-zero-day --out results-demo
```

For UNSW-NB15, point at a directory containing the official
`UNSW_NB15_training-set.csv` and `UNSW_NB15_testing-set.csv` files:

```powershell
python run_experiment.py --dataset unsw-nb15 --data-path .\data\UNSW-NB15 --target-fpr 0.01 --out results-live
```

The supplied UNSW training file is split into train/validation; the supplied test file is
kept out of model fitting and used only for evaluation. For faster iteration add `--fast`
and `--holdouts dos`; label the resulting report as a fast run. `--target-fpr` is calibrated
on benign validation rows. The production false-positive rate can differ when the source,
time period, or benign traffic mix changes.

The synthetic generator is only for pipeline development. It is not evidence of production
accuracy. CIC-IDS2017 and UNSW-NB15 are public research datasets, not cloud-provider logs.

## Run the real-time scorer

The included model is ready to use. Open PowerShell in this folder:

```powershell
$env:CLOUDIDS_API_TOKEN = (& python -c "import secrets; print(secrets.token_urlsafe(32))").Trim()
python serve_realtime.py --model .\results-live\model.joblib --db .\data\events.sqlite3
```

Open [http://127.0.0.1:8766](http://127.0.0.1:8766) for the responsive dashboard, then paste
the token from the terminal. The dashboard has Overview, Flow Events, Cloud Findings,
Models & Analysis, Integrations, Settings, and About pages. It polls the local API and keeps
the token in memory only; refresh the page and reconnect when the token has cleared.

The service binds to `127.0.0.1:8766` by default (8765 may already be used by the earlier collector). It refuses short/missing tokens. Local
endpoints:

* `GET /health` — readiness and feature count (no credential required).
* `GET /v1/schema` — required feature names; bearer token required.
* `POST /v1/flows` — score one event immediately.
* `POST /v1/flows/batch` — score 1–256 events.
* `GET /v1/alerts?limit=100` — recent alerts; bearer token required.
* `GET /v1/events?limit=100&alert=all` — scored flow stream; bearer token required.
* `GET /v1/analytics?hours=24` — hourly counts and alert-class summaries.
* `GET /v1/model` — current model metadata and benchmark metrics.
* `POST /v1/provider-findings` — normalize and store cloud-native findings.

Each scoring result includes the predicted known class, overall alert score, alert reason,
and individual supervised/autoencoder/cluster signals. An anomaly can have predicted class
`benign` when it does not resemble a trained attack family; the anomaly signal is separate.

Send a JSON event with a `features` object containing **every** feature returned by
`/v1/schema`, or a numeric array in the same order. Example shape:

```json
{
  "event_id": "sensor-1:000042",
  "features": {
    "feature_name_from_schema": 0.0
  }
}
```

The abbreviated object above illustrates the envelope only; the API intentionally rejects
missing features. Send the token in `Authorization: Bearer <token>`. Do not put this secret
in browser JavaScript: use a trusted server-side collector/proxy. To bind beyond localhost,
configure both `CLOUDIDS_TLS_CERT` and `CLOUDIDS_TLS_KEY`; remote plaintext HTTP is rejected.
`CLOUDIDS_RATE_LIMIT_PER_MINUTE` changes the per-client request limit (default 120). The API
limits bodies to 1 MiB and batches to 256 flows. It persists event IDs, predictions, signals
and timestamps for 90 days, but not raw flow features. It uses one shared bearer token and
has no user roles or tenant isolation; use a trusted backend proxy for multi-user/company
deployment. Protect or encrypt the SQLite file and backups as security data.

For example, retrieve the schema and submit a correctly shaped record with Python:

```python
import json, os
from urllib.request import Request, urlopen

base = "http://127.0.0.1:8766"
headers = {"Authorization": f"Bearer {os.environ['CLOUDIDS_API_TOKEN']}"}
with urlopen(Request(f"{base}/v1/schema", headers=headers), timeout=5) as response:
    schema = json.load(response)
features = {name: 0.0 for name in schema["features"]}  # replace with sensor-derived values
body = json.dumps({"event_id": "example-1", "features": features}).encode()
request = Request(f"{base}/v1/flows", data=body,
                  headers={**headers, "Content-Type": "application/json"})
with urlopen(request, timeout=10) as response:
    print(json.load(response))
```

Zero-filled values above are only an API shape example and are **not** a meaningful
security prediction.

### Forward cloud-native findings

The service normalizes AWS Security Hub/GuardDuty-style, Azure Defender-style, and Google
Cloud SCC-style finding envelopes. A trusted relay can forward a selected event like this:

```json
{
  "provider": "aws",
  "payload": {
    "detail": {
      "findings": [{
        "Id": "finding-123",
        "Title": "Suspicious credential activity",
        "Severity": {"Label": "HIGH"},
        "Resources": [{"Id": "resource-id"}],
        "CreatedAt": "2026-10-30T10:00:00Z"
      }]
    }
  }
}
```

Use `provider` values `aws`, `azure`, or `gcp`; the `payload` is the corresponding provider
finding envelope. Duplicate provider/finding IDs are idempotent. The normalized details
appear on the Cloud Findings page and remain separate from model predictions. Raw provider
payloads are not stored. This is an authenticated relay endpoint, **not** an account poller:
you still need to configure EventBridge/Security Hub, Defender/Activity delivery, or SCC/
Eventarc in your own cloud account and securely forward events. No account credentials are
present in this project.

## Evaluation and model limitations

* Reports show class prevalence, false positives, recall, F1, PR-AUC, ROC-AUC, confusion
  counts, balanced accuracy, MCC, per-class recall, latency and feature importance. Wilson
  95% intervals are included for thresholded precision, recall and false-positive rate; the
  intervals assume independent rows and can be too narrow for correlated host/time flows.
* A validation-set FPR target is an operating point, not a guarantee. Recalibrate and
  monitor drift using representative benign traffic from the deployment environment.
* Held-out attack-family evaluation tests one specific dataset split; it is not proof of
  general zero-day detection. Review the false-positive rate shown for every experiment.
* Feature importance describes dataset/model behavior; it is not a causal explanation.
* The provider findings relay accepts native security findings; it does not poll cloud
  accounts, collect VPC flow logs, or produce the 68 UNSW flow features. A flow collector
  must emit a compatible validated schema for ML scoring. Do not fabricate missing feature
  values. A cloud rollout still needs provider-side delivery setup, least-privilege access,
  tenant isolation, key rotation, TLS termination, retention controls, and independent
  validation on the target organization's telemetry.

## Main files

```text
cloudids/data.py          dataset loading and split protocols
cloudids/models.py        RF, XGBoost, autoencoder, K-means and hybrid detectors
cloudids/metrics.py       evaluation metrics
cloudids/experiments.py   training, evaluation, plots and model bundle
run_experiment.py         offline benchmark CLI
predict.py                batch CSV inference CLI
serve_realtime.py         authenticated live flow scoring API
```
