#!/usr/bin/env python3
"""Run the CloudIDS real-time scoring API using a trained model bundle.

Example (PowerShell):
  $env:CLOUDIDS_API_TOKEN = '<random secret, at least 32 characters>'
  python serve_realtime.py --model results_unsw/model.joblib

The API accepts already-extracted flow features. It does not capture packets or
connect to a cloud account; deploy a trusted flow/log adapter in front of it.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hmac
import json
import math
import mimetypes
import os
import re
import sqlite3
import ssl
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import joblib
import numpy as np
import pandas as pd
from cloudids.integrations import normalize_findings
from cloudids.responder import Responder


MAX_BODY_BYTES = 1_048_576
MAX_BATCH_SIZE = 256
EVENT_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
SOURCE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class ScoringService:
    def __init__(self, model_path: str, db_path: str):
        bundle = joblib.load(model_path)
        self.detector = bundle["detector"]
        self.columns = list(bundle["columns"])
        if not self.columns or len(set(self.columns)) != len(self.columns):
            raise ValueError("model bundle has an invalid feature schema")
        self.model_version = bundle.get("model_version", "legacy")
        meta_path = Path(model_path).resolve().parent / "run_meta.json"
        if meta_path.exists():
            try:
                self.model_metadata = json.loads(meta_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                self.model_metadata = {}
        else:
            self.model_metadata = {}
        self.benchmark = {}
        metrics_path = meta_path.parent / "closed_world.csv"
        if metrics_path.exists():
            try:
                metrics = pd.read_csv(metrics_path, index_col=0)
                if "Hybrid-OR" in metrics.index:
                    self.benchmark = {k: (None if pd.isna(v) else float(v))
                                      for k, v in metrics.loc["Hybrid-OR"].items()}
            except (OSError, ValueError, KeyError):
                self.benchmark = {}
        self.class_recall = {}
        recall_path = meta_path.parent / "per_class_recall.csv"
        if recall_path.exists():
            try:
                recall = pd.read_csv(recall_path, index_col=0)
                if "Hybrid-OR" in recall.columns:
                    self.class_recall = {str(k): float(v) for k, v in recall["Hybrid-OR"].items()
                                         if pd.notna(v)}
            except (OSError, ValueError, KeyError):
                self.class_recall = {}
        self.heldout_recall = {}
        heldout_path = meta_path.parent / "zero_day.csv"
        if heldout_path.exists():
            try:
                heldout = pd.read_csv(heldout_path)
                heldout = heldout[heldout["detector"] == "Hybrid-OR"]
                self.heldout_recall = {str(row.holdout): float(row.recall_holdout)
                                        for row in heldout.itertuples() if pd.notna(row.recall_holdout)}
            except (OSError, ValueError, KeyError):
                self.heldout_recall = {}
        self.db_path = str(Path(db_path).resolve())
        self.responder = Responder(str(Path(self.db_path).parent))
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.db_lock = threading.Lock()
        self.last_cleanup = time.time()
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""CREATE TABLE IF NOT EXISTS scored_events (
                event_id TEXT PRIMARY KEY,
                received_at TEXT NOT NULL,
                alert INTEGER NOT NULL,
                score REAL NOT NULL,
                reason TEXT NOT NULL,
                predicted_class TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT 'unspecified',
                signals_json TEXT NOT NULL
            )""")
            columns = {row[1] for row in conn.execute("PRAGMA table_info(scored_events)")}
            if "predicted_class" not in columns:
                conn.execute("ALTER TABLE scored_events ADD COLUMN predicted_class TEXT NOT NULL DEFAULT ''")
            if "source" not in columns:
                conn.execute("ALTER TABLE scored_events ADD COLUMN source TEXT NOT NULL DEFAULT 'unspecified'")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scored_received ON scored_events(received_at)")
            conn.execute("""CREATE TABLE IF NOT EXISTS provider_findings (
                provider TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                received_at TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                resource TEXT NOT NULL,
                description TEXT NOT NULL,
                PRIMARY KEY(provider, finding_id)
            )""")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_received ON provider_findings(received_at)")
            conn.execute("DELETE FROM scored_events WHERE received_at < ?",
                         (datetime.fromtimestamp(time.time() - 90 * 86400, timezone.utc).isoformat(),))

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.execute("PRAGMA busy_timeout=10000")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def score(self, events: list[dict]):
        ids, rows, sources = [], [], []
        for event in events:
            if not isinstance(event, dict):
                raise ValueError("each event must be a JSON object")
            event_id = event.get("event_id") or str(uuid.uuid4())
            if not isinstance(event_id, str) or not EVENT_ID_RE.fullmatch(event_id):
                raise ValueError("event_id must contain 1-128 letters, numbers, '.', '_', ':', or '-'")
            source = event.get("source", "unspecified")
            if not isinstance(source, str) or not SOURCE_RE.fullmatch(source):
                raise ValueError("source must be 1-80 letters, numbers, '.', '_', ':', or '-'")
            features = event.get("features")
            if isinstance(features, dict):
                missing = set(self.columns) - set(features)
                extra = set(features) - set(self.columns)
                if missing or extra:
                    raise ValueError(f"feature schema mismatch: missing={sorted(missing)[:8]}, "
                                     f"unexpected={sorted(extra)[:8]}")
                values = [features[c] for c in self.columns]
            elif isinstance(features, list) and len(features) == len(self.columns):
                values = features
            else:
                raise ValueError("features must be a name/value object or a list matching the model schema")
            try:
                valid_values = all(not isinstance(v, bool) and isinstance(v, (int, float)) and
                                   math.isfinite(float(v)) and
                                   abs(float(v)) <= np.finfo(np.float32).max for v in values)
            except (OverflowError, ValueError):
                valid_values = False
            if not valid_values:
                raise ValueError("all feature values must be finite JSON numbers")
            ids.append(event_id)
            rows.append(values)
            sources.append(source)

        frame = pd.DataFrame(rows, columns=self.columns, dtype=np.float32)
        flags, scores = self.detector.decision(frame)
        if hasattr(self.detector, "signals"):
            signals = self.detector.signals(frame)
        else:
            signals = {"known_attack": flags, "autoencoder_anomaly": np.zeros(len(frame), bool),
                       "cluster_anomaly": np.zeros(len(frame), bool)}
        reasons = (self.detector.explain(frame) if hasattr(self.detector, "explain") else
                   np.where(flags, "attack", "benign"))
        classifier = getattr(self.detector, "sup", None)
        predicted_classes = (classifier.predict_label(frame) if classifier is not None else
                             np.full(len(frame), "unknown", dtype=object))
        received_at = utc_now()
        results = []
        with self.db_lock, self._connect() as conn:
            for i, event_id in enumerate(ids):
                row = {
                    "event_id": event_id,
                    "received_at": received_at,
                    "alert": bool(flags[i]),
                    "score": float(scores[i]),
                    "reason": str(reasons[i]),
                    "predicted_class": str(predicted_classes[i]),
                    "source": sources[i],
                    "signals": {key: bool(value[i]) for key, value in signals.items()},
                    "model_version": self.model_version,
                }
                conn.execute("INSERT OR IGNORE INTO scored_events "
                             "(event_id, received_at, alert, score, reason, predicted_class, source, signals_json) "
                             "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                             (event_id, received_at, int(row["alert"]), row["score"], row["reason"],
                              row["predicted_class"], row["source"],
                              json.dumps(row["signals"], separators=(",", ":"))))
                # Idempotent retries return the first persisted result for that event ID.
                stored = conn.execute("SELECT received_at, alert, score, reason, predicted_class, source, signals_json "
                                      "FROM scored_events WHERE event_id=?", (event_id,)).fetchone()
                row.update({"received_at": stored[0], "alert": bool(stored[1]),
                            "score": stored[2], "reason": stored[3],
                            "predicted_class": stored[4], "source": stored[5],
                            "signals": json.loads(stored[6])})
                results.append(row)
            if time.time() - self.last_cleanup >= 3600:
                cutoff = datetime.fromtimestamp(time.time() - 90 * 86400, timezone.utc).isoformat()
                conn.execute("DELETE FROM scored_events WHERE received_at < ?", (cutoff,))
                conn.execute("DELETE FROM provider_findings WHERE received_at < ?", (cutoff,))
                self.last_cleanup = time.time()
        self.responder.handle(results, events)
        return results

    def alerts(self, limit: int, since: str | None):
        query = ("SELECT event_id, received_at, score, reason, predicted_class, source, signals_json "
                 "FROM scored_events WHERE alert=1")
        params = []
        if since:
            query += " AND received_at >= ?"
            params.append(since)
        query += " ORDER BY received_at DESC LIMIT ?"
        params.append(limit)
        with self.db_lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [{"event_id": r[0], "received_at": r[1], "alert": True, "score": r[2],
                 "reason": r[3], "predicted_class": r[4], "source": r[5], "signals": json.loads(r[6]),
                 "model_version": self.model_version}
                for r in rows]

    def events(self, limit: int, since: str | None, alert: bool | None):
        query = ("SELECT event_id, received_at, alert, score, reason, predicted_class, source, signals_json "
                 "FROM scored_events WHERE 1=1")
        params = []
        if since:
            query += " AND received_at >= ?"
            params.append(since)
        if alert is not None:
            query += " AND alert = ?"
            params.append(int(alert))
        query += " ORDER BY received_at DESC LIMIT ?"
        params.append(limit)
        with self.db_lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [{"event_id": r[0], "received_at": r[1], "alert": bool(r[2]), "score": r[3],
                 "reason": r[4], "predicted_class": r[5], "source": r[6],
                 "signals": json.loads(r[7]), "model_version": self.model_version}
                for r in rows]

    def analytics(self, hours: int = 24):
        now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        since = (now - pd.Timedelta(hours=hours - 1)).isoformat(timespec="milliseconds")
        with self.db_lock, self._connect() as conn:
            totals = conn.execute("SELECT COUNT(*), COALESCE(SUM(alert),0), COALESCE(AVG(score),0) "
                                  "FROM scored_events WHERE received_at >= ?", (since,)).fetchone()
            hourly_rows = conn.execute("SELECT substr(received_at,1,13), COUNT(*), COALESCE(SUM(alert),0) "
                                       "FROM scored_events WHERE received_at >= ? GROUP BY 1", (since,)).fetchall()
            classes = conn.execute("SELECT predicted_class, COUNT(*) FROM scored_events "
                                   "WHERE alert=1 AND received_at >= ? GROUP BY predicted_class "
                                   "ORDER BY COUNT(*) DESC LIMIT 8", (since,)).fetchall()
            sources = conn.execute("SELECT source, COUNT(*) FROM scored_events "
                                   "WHERE received_at >= ? GROUP BY source ORDER BY COUNT(*) DESC LIMIT 8",
                                   (since,)).fetchall()
            finding_counts = conn.execute("SELECT provider, COUNT(*) FROM provider_findings "
                                          "WHERE received_at >= ? GROUP BY provider", (since,)).fetchall()
        hourly = {r[0]: {"events": r[1], "alerts": r[2]} for r in hourly_rows}
        series = []
        for offset in range(hours - 1, -1, -1):
            stamp = (now - pd.Timedelta(hours=offset)).strftime("%Y-%m-%dT%H")
            counts = hourly.get(stamp, {"events": 0, "alerts": 0})
            series.append({"hour": stamp + ":00:00Z", **counts})
        return {"hours": hours, "events": totals[0], "alerts": totals[1],
                "mean_score": float(totals[2]), "series": series,
                "attack_classes": [{"name": r[0], "count": r[1]} for r in classes],
                "sources": [{"name": r[0], "count": r[1]} for r in sources],
                "provider_findings": {r[0]: r[1] for r in finding_counts}}

    def ingest_findings(self, provider: str, payload: dict):
        findings = normalize_findings(provider, payload)
        received_at = utc_now()
        with self.db_lock, self._connect() as conn:
            new_count = 0
            for finding in findings:
                cur = conn.execute("INSERT OR IGNORE INTO provider_findings "
                                   "(provider, finding_id, received_at, occurred_at, title, severity, "
                                   "category, resource, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                   (provider, finding["finding_id"], received_at, finding["occurred_at"],
                                    finding["title"], finding["severity"], finding["category"],
                                    finding["resource"], finding["description"]))
                new_count += cur.rowcount
        return {"received": len(findings), "new": new_count, "duplicates": len(findings) - new_count}

    def provider_findings(self, limit: int, provider: str | None = None):
        query = ("SELECT provider, finding_id, received_at, occurred_at, title, severity, category, "
                 "resource, description FROM provider_findings")
        params = []
        if provider:
            query += " WHERE provider=?"
            params.append(provider)
        query += " ORDER BY received_at DESC LIMIT ?"
        params.append(limit)
        with self.db_lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        keys = ("provider", "finding_id", "received_at", "occurred_at", "title", "severity",
                "category", "resource", "description")
        return [dict(zip(keys, row)) for row in rows]


def create_handler(service: ScoringService, token: str):
    request_lock = threading.Lock()
    request_times: dict[str, list[float]] = {}
    request_limit = max(1, int(os.getenv("CLOUDIDS_RATE_LIMIT_PER_MINUTE", "120")))

    def model_classes():
        classifier = getattr(service.detector, "sup", None)
        return [str(value) for value in classifier.le_.classes_] if classifier is not None else []

    class Handler(BaseHTTPRequestHandler):
        server_version = "CloudIDS/1"
        sys_version = ""

        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, fmt, *args):
            # Do not log authorization headers or request bodies.
            sys.stderr.write("%s %s\n" % (self.log_date_time_string(), fmt % args))

        def _send(self, status: int, payload, extra_headers=None):
            raw = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'")
            for key, value in (extra_headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(raw)

        def _send_static(self, path: str):
            allowed = {"/": "index.html", "/index.html": "index.html",
                       "/static/app.css": "app.css", "/static/app.js": "app.js"}
            name = allowed.get(path)
            if not name:
                self._send(404, {"error": "not found"})
                return
            file_path = Path(__file__).resolve().parent / "static" / name
            try:
                body = file_path.read_bytes()
            except OSError:
                self._send(503, {"error": "dashboard asset unavailable"})
                return
            self.send_response(200)
            self.send_header("Content-Type", mimetypes.guess_type(name)[0] or "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; script-src 'self'; style-src 'self'; "
                             "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
                             "base-uri 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self):
            supplied = self.headers.get("Authorization", "")
            prefix = "Bearer "
            return supplied.startswith(prefix) and hmac.compare_digest(supplied[len(prefix):], token)

        def _rate_limited(self):
            # Use the socket peer address; ignore spoofable forwarded-for headers.
            peer = self.client_address[0]
            now = time.monotonic()
            with request_lock:
                recent = [t for t in request_times.get(peer, []) if now - t < 60]
                if len(recent) >= request_limit:
                    request_times[peer] = recent
                    return True
                recent.append(now)
                if len(request_times) > 10000:
                    request_times.clear()
                request_times[peer] = recent
            return False

        def _body(self):
            if self.headers.get_content_type() != "application/json":
                raise ValueError("Content-Type must be application/json")
            length = self.headers.get("Content-Length")
            if not length or not length.isdigit():
                raise ValueError("Content-Length is required")
            if int(length) > MAX_BODY_BYTES:
                raise OverflowError("request body exceeds the 1 MiB limit")
            raw = self.rfile.read(int(length))
            if len(raw) != int(length):
                raise ValueError("incomplete request body")
            try:
                return json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("request body must be valid UTF-8 JSON") from exc

        def do_GET(self):
            path = urlparse(self.path)
            if path.path in ("/", "/index.html", "/static/app.css", "/static/app.js"):
                self._send_static(path.path)
                return
            if path.path == "/health":
                self._send(200, {"status": "ready", "model_version": service.model_version,
                                 "feature_count": len(service.columns), "time": utc_now()})
                return
            if path.path == "/v1/schema":
                if not self._authorized():
                    self._send(401, {"error": "unauthorized"})
                    return
                if self._rate_limited():
                    self._send(429, {"error": "rate limit exceeded"}, {"Retry-After": "60"})
                    return
                self._send(200, {"model_version": service.model_version,
                                 "feature_count": len(service.columns), "features": service.columns,
                                 "known_classes": model_classes()})
                return
            if path.path not in ("/v1/alerts", "/v1/events", "/v1/analytics",
                                 "/v1/model", "/v1/provider-findings"):
                self._send(404, {"error": "not found"})
                return
            if not self._authorized():
                self._send(401, {"error": "unauthorized"})
                return
            if self._rate_limited():
                self._send(429, {"error": "rate limit exceeded"}, {"Retry-After": "60"})
                return
            query = parse_qs(path.query)
            if path.path == "/v1/model":
                meta = service.model_metadata
                self._send(200, {"model_version": service.model_version,
                                 "dataset": meta.get("dataset", "unknown"),
                                 "features": len(service.columns),
                                 "classes": model_classes(),
                                 "target_fpr": meta.get("target_fpr"),
                                 "evaluation_profile": ("fast" if meta.get("fast_profile") else "full"),
                                 "official_test_partition": meta.get("official_test_partition", False),
                                 "test_attack_prevalence": meta.get("test_attack_prevalence"),
                                 "benchmark": service.benchmark,
                                 "class_recall": service.class_recall,
                                 "heldout_recall": service.heldout_recall})
                return
            if path.path == "/v1/analytics":
                try:
                    hours = int(query.get("hours", ["24"])[0])
                    if hours not in {6, 24, 72, 168}:
                        raise ValueError
                except ValueError:
                    self._send(400, {"error": "hours must be 6, 24, 72, or 168"})
                    return
                self._send(200, service.analytics(hours))
                return
            if path.path == "/v1/provider-findings":
                try:
                    limit = int(query.get("limit", ["100"])[0])
                    if not 1 <= limit <= 500:
                        raise ValueError
                except ValueError:
                    self._send(400, {"error": "limit must be between 1 and 500"})
                    return
                provider = query.get("provider", [None])[0]
                self._send(200, {"findings": service.provider_findings(limit, provider)})
                return
            try:
                limit = int(query.get("limit", ["100"])[0])
                if not 1 <= limit <= 500:
                    raise ValueError
            except ValueError:
                self._send(400, {"error": "limit must be between 1 and 500"})
                return
            if path.path == "/v1/alerts":
                self._send(200, {"alerts": service.alerts(limit, query.get("since", [None])[0])})
                return
            if path.path == "/v1/events":
                alert_arg = query.get("alert", ["all"])[0].lower()
                if alert_arg not in {"all", "true", "false"}:
                    self._send(400, {"error": "alert must be all, true, or false"})
                    return
                alert = None if alert_arg == "all" else alert_arg == "true"
                self._send(200, {"events": service.events(limit, query.get("since", [None])[0], alert)})

        def do_POST(self):
            path = urlparse(self.path).path
            if path not in ("/v1/flows", "/v1/flows/batch", "/v1/provider-findings"):
                self._send(404, {"error": "not found"})
                return
            if not self._authorized():
                self._send(401, {"error": "unauthorized"})
                return
            if self._rate_limited():
                self._send(429, {"error": "rate limit exceeded; retry after 60 seconds"})
                return
            try:
                payload = self._body()
                if path == "/v1/provider-findings":
                    if not isinstance(payload, dict):
                        raise ValueError("request must be a JSON object")
                    provider = payload.get("provider")
                    result = service.ingest_findings(provider, payload.get("payload"))
                    self._send(200, result)
                    return
                if isinstance(payload, dict) and urlparse(self.path).path == "/v1/flows":
                    events = [payload]
                elif isinstance(payload, dict):
                    events = payload.get("events")
                else:
                    events = payload
                if not isinstance(events, list) or not 1 <= len(events) <= MAX_BATCH_SIZE:
                    self._send(400, {"error": f"submit 1-{MAX_BATCH_SIZE} flow events"})
                    return
                result = service.score(events)
                self._send(200, {"results": result, "count": len(result)})
            except OverflowError as exc:
                self._send(413, {"error": str(exc)})
            except ValueError as exc:
                self._send(400, {"error": str(exc)})
            except Exception as exc:
                sys.stderr.write(f"Scoring failure: {type(exc).__name__}\n")
                self._send(500, {"error": "scoring failed; consult server logs"})

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default=os.getenv("CLOUDIDS_MODEL_PATH", "results-live/model.joblib"))
    parser.add_argument("--db", default=os.getenv("CLOUDIDS_EVENT_DB", "data/cloudids-events.sqlite3"))
    parser.add_argument("--host", default=os.getenv("CLOUDIDS_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("CLOUDIDS_PORT", "8766")))
    args = parser.parse_args()

    token = os.getenv("CLOUDIDS_API_TOKEN", "")
    if len(token) < 32:
        parser.error("set CLOUDIDS_API_TOKEN to a randomly generated secret of at least 32 characters")
    if args.host not in ("127.0.0.1", "localhost", "::1") and not (
            os.getenv("CLOUDIDS_TLS_CERT") and os.getenv("CLOUDIDS_TLS_KEY")):
        parser.error("non-localhost binding requires CLOUDIDS_TLS_CERT and CLOUDIDS_TLS_KEY")
    if bool(os.getenv("CLOUDIDS_TLS_CERT")) != bool(os.getenv("CLOUDIDS_TLS_KEY")):
        parser.error("set both CLOUDIDS_TLS_CERT and CLOUDIDS_TLS_KEY, or neither")
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    service = ScoringService(args.model, args.db)
    class BoundedHTTPServer(ThreadingHTTPServer):
        request_queue_size = 64
        slots = threading.BoundedSemaphore(32)

        def process_request(self, request, client_address):
            if not self.slots.acquire(blocking=False):
                self.shutdown_request(request)
                return
            try:
                super().process_request(request, client_address)
            except Exception:
                self.slots.release()
                raise

        def process_request_thread(self, request, client_address):
            try:
                super().process_request_thread(request, client_address)
            finally:
                self.slots.release()

    server = BoundedHTTPServer((args.host, args.port), create_handler(service, token))
    server.daemon_threads = True
    cert, key = os.getenv("CLOUDIDS_TLS_CERT"), os.getenv("CLOUDIDS_TLS_KEY")
    if cert and key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    else:
        scheme = "http"
    print(f"CloudIDS scoring API ready at {scheme}://{args.host}:{args.port} "
          f"({len(service.columns)} features, model {service.model_version})", flush=True)
    print(f"Responder -> {service.responder.describe()}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping CloudIDS API", flush=True)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
