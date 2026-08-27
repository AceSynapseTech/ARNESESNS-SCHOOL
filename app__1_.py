"""
ARNESEN'S COMPREHENSIVE SCHOOL ERP - Backend
=============================================
Single-file Flask API that gives the (otherwise fully client-side,
IndexedDB-based) frontend a cloud backup/restore layer on top of
Backblaze B2, using B2's S3-compatible API via boto3.

The frontend already builds a full JSON "dump" of every IndexedDB store
for its manual Backup/Restore buttons -- this backend just gives it
somewhere to push/pull that same JSON blob from, instead of only a
local file download.

ENDPOINTS
---------
GET    /api/health                  liveness check (no auth)
POST   /api/backup                  upload a full JSON dump -> new timestamped backup + updates "latest"
GET    /api/backups                 list stored backups, newest first
GET    /api/backup/latest           fetch the most recent backup
GET    /api/backup/<key>            fetch one specific backup by its key
DELETE /api/backup/<key>            delete one specific backup

AUTH
----
Every /api/backup* request must include header:
    X-API-Key: <API_AUTH_TOKEN>
matching the API_AUTH_TOKEN env var below (this data is the whole
school's records, so don't leave this unset in production).

CONFIGURATION (environment variables)
--------------------------------------
B2_KEY_ID            Backblaze "keyID" (from Application Keys)
B2_APPLICATION_KEY   Backblaze "applicationKey"
B2_BUCKET            Bucket name, e.g. "arnesens"
B2_ENDPOINT          e.g. https://s3.eu-central-003.backblazeb2.com
API_AUTH_TOKEN       Shared secret the frontend must send in X-API-Key
PORT                 Port to listen on (default 5000)

RUN
---
    pip install -r requirements.txt
    export B2_KEY_ID=...
    export B2_APPLICATION_KEY=...
    export B2_BUCKET=arnesens
    export B2_ENDPOINT=https://s3.eu-central-003.backblazeb2.com
    export API_AUTH_TOKEN=some-long-random-string
    python app.py
"""

import os
import json
import datetime
import functools

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError
from flask import Flask, request, jsonify, abort
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # allow the frontend (served from anywhere) to call this API

# ---------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------
B2_KEY_ID = os.environ.get("B2_KEY_ID")
B2_APPLICATION_KEY = os.environ.get("B2_APPLICATION_KEY")
B2_BUCKET = os.environ.get("B2_BUCKET", "arnesens")
B2_ENDPOINT = os.environ.get("B2_ENDPOINT", "https://s3.eu-central-003.backblazeb2.com")
API_AUTH_TOKEN = os.environ.get("API_AUTH_TOKEN")  # if unset, auth is skipped (dev only)

BACKUP_PREFIX = "backups/"
LATEST_KEY = f"{BACKUP_PREFIX}latest.json"

_s3_client = None


def s3():
    """Lazily build a boto3 S3 client pointed at the Backblaze B2 endpoint."""
    global _s3_client
    if _s3_client is None:
        if not (B2_KEY_ID and B2_APPLICATION_KEY):
            raise RuntimeError("B2_KEY_ID / B2_APPLICATION_KEY environment variables are not set")
        _s3_client = boto3.client(
            "s3",
            endpoint_url=B2_ENDPOINT,
            aws_access_key_id=B2_KEY_ID,
            aws_secret_access_key=B2_APPLICATION_KEY,
            config=Config(signature_version="s3v4"),
        )
    return _s3_client


def require_api_key(fn):
    """Guard /api/backup* routes with a shared-secret header."""
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if API_AUTH_TOKEN:
            supplied = request.headers.get("X-API-Key")
            if supplied != API_AUTH_TOKEN:
                abort(401, description="Invalid or missing X-API-Key header")
        return fn(*args, **kwargs)
    return wrapper


@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(404)
@app.errorhandler(500)
def handle_error(e):
    return jsonify(error=str(getattr(e, "description", e))), getattr(e, "code", 500)


# ---------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------
@app.get("/")
def index():
    """Simple landing page so hitting the bare URL doesn't 404 (Render
    pings this, browsers hit it, etc.). The real API lives under /api/*."""
    return jsonify(
        service="Arnesen's Comprehensive School ERP - Backup API",
        status="running",
        bucket=B2_BUCKET,
        endpoints=[
            "GET /api/health",
            "POST /api/backup",
            "GET /api/backups",
            "GET /api/backup/latest",
            "GET /api/backup/<key>",
            "DELETE /api/backup/<key>",
        ],
    )


@app.get("/favicon.ico")
def favicon():
    return "", 204


@app.get("/api/health")
def health():
    return jsonify(
        status="ok",
        bucket=B2_BUCKET,
        endpoint=B2_ENDPOINT,
        time=datetime.datetime.utcnow().isoformat() + "Z",
    )


@app.post("/api/backup")
@require_api_key
def create_backup():
    """Accepts the full JSON dump (same shape as the app's manual
    'Backup (JSON)' export) and stores it in B2 as a timestamped
    object, plus overwrites a 'latest.json' pointer for quick restore."""
    payload = request.get_json(silent=True)
    if payload is None:
        abort(400, description="Request body must be valid JSON")

    body = json.dumps(payload).encode("utf-8")
    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    key = f"{BACKUP_PREFIX}{ts}.json"

    client = s3()
    try:
        client.put_object(Bucket=B2_BUCKET, Key=key, Body=body, ContentType="application/json")
        client.put_object(Bucket=B2_BUCKET, Key=LATEST_KEY, Body=body, ContentType="application/json")
    except ClientError as e:
        abort(500, description=f"Backblaze upload failed: {e}")

    return jsonify(ok=True, key=key, sizeBytes=len(body), time=ts)


@app.get("/api/backups")
@require_api_key
def list_backups():
    client = s3()
    try:
        resp = client.list_objects_v2(Bucket=B2_BUCKET, Prefix=BACKUP_PREFIX)
    except ClientError as e:
        abort(500, description=f"Backblaze list failed: {e}")

    items = []
    for obj in resp.get("Contents", []):
        if obj["Key"] == LATEST_KEY:
            continue
        items.append({
            "key": obj["Key"],
            "sizeBytes": obj["Size"],
            "lastModified": obj["LastModified"].isoformat(),
        })
    items.sort(key=lambda x: x["key"], reverse=True)
    return jsonify(backups=items)


@app.get("/api/backup/latest")
@require_api_key
def get_latest_backup():
    return _fetch_key(LATEST_KEY)


@app.get("/api/backup/<path:key>")
@require_api_key
def get_backup(key):
    full_key = key if key.startswith(BACKUP_PREFIX) else f"{BACKUP_PREFIX}{key}"
    return _fetch_key(full_key)


@app.delete("/api/backup/<path:key>")
@require_api_key
def delete_backup(key):
    full_key = key if key.startswith(BACKUP_PREFIX) else f"{BACKUP_PREFIX}{key}"
    if full_key == LATEST_KEY:
        abort(400, description="Refusing to delete the 'latest' pointer directly")
    client = s3()
    try:
        client.delete_object(Bucket=B2_BUCKET, Key=full_key)
    except ClientError as e:
        abort(500, description=f"Backblaze delete failed: {e}")
    return jsonify(ok=True, deleted=full_key)


def _fetch_key(key):
    client = s3()
    try:
        obj = client.get_object(Bucket=B2_BUCKET, Key=key)
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code in ("NoSuchKey", "404"):
            abort(404, description="Backup not found")
        abort(500, description=f"Backblaze fetch failed: {e}")

    data = obj["Body"].read()
    try:
        parsed = json.loads(data)
    except json.JSONDecodeError:
        abort(500, description="Stored backup object is not valid JSON")
    return jsonify(parsed)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
