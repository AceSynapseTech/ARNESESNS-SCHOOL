#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================================
 ARNESEN'S COMPREHENSIVE SCHOOL — BACKEND (app.py)
============================================================================
Single-file Flask backend that serves the existing
`arnesens-school-management-system.html` frontend and backs it with:

  * PostgreSQL  — single source of truth for ALL structured school data
                  (users, pupils, teachers, classes, subjects, exams, marks,
                  grading, attendance, fees, timetables, discipline, library,
                  inventory, HR, communication, document metadata, activity
                  logs, settings — everything the frontend used to keep in
                  IndexedDB).

  * Backblaze B2 — private, S3-compatible object storage for every actual
                  uploaded/generated FILE (photos, logos, documents, report
                  card PDFs, backups, imports/exports). PostgreSQL never
                  stores file bytes — only file metadata + the B2 object key.

Architecture
------------
The frontend historically persisted everything through one narrow chokepoint:
an IndexedDB wrapper with getAll/get/put/bulkPut/delete/clear, driving 30
named "stores" (users, students, teachers, classes, ...). This backend
mirrors that exact shape with a single generic `records` table
(store, id, data JSONB) so the *entire* existing frontend business logic
(rendering, computations, report cards, analysis, etc.) keeps working
against the same shapes it already expects — only the persistence layer
moves from local IndexedDB to this centralized, authenticated API.

Files are handled separately and explicitly: every upload goes through
validation + permission checks + Backblaze, and PostgreSQL only ever stores
a `files` metadata row (object_key, size, uploader, etc.) — never binary
data, never a permanent public URL.

============================================================================
REQUIRED ENVIRONMENT VARIABLES
============================================================================
    SECRET_KEY=                        Flask session-signing secret (long random string)
    DATABASE_URL=                      postgresql+psycopg://user:pass@host:5432/dbname

    B2_ENDPOINT_URL=https://s3.eu-central-003.backblazeb2.com
    B2_BUCKET_NAME=arnesens
    B2_BUCKET_ID=0280038885bf4027a50d0d15
    B2_KEY_ID=                         Backblaze applicationKeyId (SECRET — server side only)
    B2_APPLICATION_KEY=                Backblaze applicationKey   (SECRET — server side only)
    B2_REGION=eu-central-003

    PORT=5000
    FLASK_ENV=production                "production" enables secure cookies etc.

Optional:
    AI_API_KEY=                        only needed if the AI assistant feature is enabled
    CORS_ALLOWED_ORIGINS=              comma-separated list — ONLY if the HTML is served
                                        from a different origin than this API. Leave unset
                                        for same-domain deployment (recommended).
    PRESIGNED_URL_EXPIRY_SECONDS=300   default expiry for generated download URLs
    MAX_UPLOAD_MB=25                   hard cap per uploaded file
    ADMIN_DEFAULT_USERNAME=admin       first-run seed admin username
    ADMIN_DEFAULT_PASSWORD=            first-run seed admin password. If unset, a random
                                        password is generated and printed ONCE to the
                                        server log on first boot — change it immediately.

Never put real secret values in source control. Use a `.env` file locally
(loaded automatically via python-dotenv) or your host's secret manager in
production.

============================================================================
RUNNING
============================================================================
    pip install flask flask-sqlalchemy flask-login flask-limiter flask-cors \
                "psycopg[binary]" boto3 python-dotenv werkzeug gunicorn

    Local dev:    python app.py
    Production:   gunicorn -w 4 --threads 4 --timeout 90 -b 0.0.0.0:$PORT app:app

    4 workers x 4 threads with a pooled PostgreSQL connection (configured
    below) comfortably serves 100+ concurrent users from anywhere in the
    world; scale `-w` with available CPU cores on the host.
============================================================================
"""

import os
import io
import re
import csv
import json
import math
import time
import uuid
import hashlib
import secrets
import logging
import mimetypes
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, request, jsonify, session, g, abort, Response, stream_with_context
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user, login_required, current_user,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import SQLAlchemyError

import boto3
from botocore.client import Config as BotoConfig
from botocore.exceptions import ClientError, BotoCoreError

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    from flask_cors import CORS
except ImportError:
    CORS = None


# ============================================================================
# 1. LOGGING  (never log secrets, passwords, tokens, or presigned URLs)
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s [%(name)s] %(message)s',
)
log = logging.getLogger('arnesens')

_SECRET_ENV_KEYS = {'B2_KEY_ID', 'B2_APPLICATION_KEY', 'SECRET_KEY', 'DATABASE_URL', 'AI_API_KEY'}


def _redact(msg: str) -> str:
    """Best-effort scrub of anything that looks like a secret before it hits a log line."""
    for key in _SECRET_ENV_KEYS:
        val = os.environ.get(key)
        if val and len(val) > 6 and val in msg:
            msg = msg.replace(val, '***REDACTED***')
    return msg


# ============================================================================
# 2. CONFIG
# ============================================================================
def _required_env(name):
    val = os.environ.get(name)
    if not val:
        raise RuntimeError(f'Missing required environment variable: {name}')
    return val


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    SQLALCHEMY_DATABASE_URI = _required_env('DATABASE_URL')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Pool sized for 100+ concurrent users behind a multi-worker gunicorn deployment.
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_size': int(os.environ.get('DB_POOL_SIZE', 15)),
        'max_overflow': int(os.environ.get('DB_MAX_OVERFLOW', 25)),
        'pool_pre_ping': True,
        'pool_recycle': 280,
    }
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_UPLOAD_MB', 25)) * 1024 * 1024
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV', 'production') == 'production'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)
    JSON_SORT_KEYS = False


app = Flask(__name__)
app.config.from_object(Config)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)  # correct client IP/scheme behind a reverse proxy

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.session_protection = 'strong'

limiter = Limiter(get_remote_address, app=app, default_limits=['1200 per hour'], storage_uri='memory://')
# NOTE: 'memory://' limiter storage is per-process. If you deploy with more than one
# gunicorn worker/machine, point this at Redis instead (storage_uri='redis://...') so
# rate limits are enforced consistently across all workers.

_allowed_origins = [o.strip() for o in os.environ.get('CORS_ALLOWED_ORIGINS', '').split(',') if o.strip()]
if CORS and _allowed_origins:
    CORS(app, supports_credentials=True, origins=_allowed_origins)
    log.info('CORS enabled for explicit origins: %s', _allowed_origins)
else:
    log.info('CORS not enabled (same-origin deployment assumed). Set CORS_ALLOWED_ORIGINS to change this.')


# ============================================================================
# 3. DATABASE MODELS
# ============================================================================

# The exact 30 "stores" the existing frontend already manages via IndexedDB.
# Kept as one generic, JSONB-backed table so the frontend's data shapes need
# no redesign — only its persistence transport changes (IndexedDB -> this API).
STORE_NAMES = [
    'users', 'students', 'teachers', 'classes', 'subjects', 'exams', 'marks',
    'attendance', 'feeStructures', 'feePayments', 'grading', 'cbcGrading', 'announcements',
    'books', 'borrows', 'timetable', 'timetableRules', 'settings', 'activity', 'discipline',
    'inventoryItems', 'suppliers', 'stockMovements', 'assets',
    'leaveRequests', 'payrollRecords', 'appraisals', 'staffDocuments',
    'leaveOuts', 'teachingAssignments',
]


class Record(db.Model):
    """One row per (store, id) — the PostgreSQL mirror of an IndexedDB record.
    `data` is the exact JSON object the frontend already works with."""
    __tablename__ = 'records'
    store = db.Column(db.String(64), primary_key=True)
    id = db.Column(db.String(128), primary_key=True)
    data = db.Column(JSONB, nullable=False)
    updated_by = db.Column(db.String(128), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now(),
                            onupdate=db.func.now(), nullable=False)

    __table_args__ = (
        db.Index('ix_records_store', 'store'),
    )


class FileMeta(db.Model):
    """File metadata. The actual bytes live in Backblaze B2 under `object_key`.
    This table is the ONLY source of truth for what files exist and who may
    access them — the object_key itself is never exposed to the browser."""
    __tablename__ = 'files'
    id = db.Column(db.String(64), primary_key=True)
    original_filename = db.Column(db.String(512), nullable=False)
    stored_filename = db.Column(db.String(512), nullable=False)
    object_key = db.Column(db.String(1024), nullable=False, unique=True)
    bucket_name = db.Column(db.String(128), nullable=False)
    content_type = db.Column(db.String(128))
    file_size = db.Column(db.BigInteger)
    checksum = db.Column(db.String(128))  # sha256 hex digest
    category = db.Column(db.String(64), index=True, nullable=False)
    uploaded_by = db.Column(db.String(128))
    created_at = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), nullable=False)
    related_entity_type = db.Column(db.String(64), index=True)
    related_entity_id = db.Column(db.String(128), index=True)
    deleted_at = db.Column(db.DateTime(timezone=True), nullable=True)  # soft delete; B2 object removed on hard cleanup

    def public_json(self):
        """Safe to return to authorized clients — no object_key, no bucket internals."""
        return {
            'id': self.id,
            'originalFilename': self.original_filename,
            'contentType': self.content_type,
            'fileSize': self.file_size,
            'category': self.category,
            'uploadedBy': self.uploaded_by,
            'createdAt': self.created_at.isoformat() if self.created_at else None,
            'relatedEntityType': self.related_entity_type,
            'relatedEntityId': self.related_entity_id,
            'url': f'/api/files/{self.id}/stream',
        }


# ============================================================================
# 4. BACKBLAZE B2 (S3-compatible) CLIENT
# ============================================================================
B2_ENDPOINT_URL = os.environ.get('B2_ENDPOINT_URL', 'https://s3.eu-central-003.backblazeb2.com')
B2_BUCKET_NAME = os.environ.get('B2_BUCKET_NAME', 'arnesens')
B2_BUCKET_ID = os.environ.get('B2_BUCKET_ID', '')
B2_REGION = os.environ.get('B2_REGION', 'eu-central-003')
PRESIGNED_URL_EXPIRY_SECONDS = int(os.environ.get('PRESIGNED_URL_EXPIRY_SECONDS', 300))

_b2_key_id = os.environ.get('B2_KEY_ID')
_b2_app_key = os.environ.get('B2_APPLICATION_KEY')
if not _b2_key_id or not _b2_app_key:
    log.warning('B2_KEY_ID / B2_APPLICATION_KEY are not set — file uploads/downloads will fail '
                'until these are configured as environment variables.')

_b2_client = boto3.client(
    's3',
    endpoint_url=B2_ENDPOINT_URL,
    aws_access_key_id=_b2_key_id,
    aws_secret_access_key=_b2_app_key,
    region_name=B2_REGION,
    config=BotoConfig(signature_version='s3v4', retries={'max_attempts': 3, 'mode': 'standard'}),
)


def b2_configured() -> bool:
    return bool(_b2_key_id and _b2_app_key and B2_BUCKET_NAME)


# ----------------------------------------------------------------------
# Upload categories: allowed extensions/MIME types + path-builder + max size
# ----------------------------------------------------------------------
IMAGE_EXTENSIONS = {'jpg', 'jpeg', 'png', 'webp'}
IMAGE_MIMES = {'image/jpeg', 'image/png', 'image/webp'}
DOC_EXTENSIONS = {'pdf', 'docx', 'xlsx', 'csv'}
DOC_MIMES = {
    'application/pdf',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'text/csv', 'application/csv', 'application/vnd.ms-excel',
}
DANGEROUS_EXTENSIONS = {
    'exe', 'msi', 'bat', 'cmd', 'sh', 'ps1', 'com', 'scr', 'js', 'jar', 'php',
    'py', 'rb', 'pl', 'cgi', 'asp', 'aspx', 'jsp', 'dll', 'so', 'apk', 'app',
    'vbs', 'wsf', 'htaccess', 'html', 'htm',
}

# category -> (allowed_extensions, allowed_mimes, max_mb, key_builder)
CATEGORIES = {
    'school-logo': (IMAGE_EXTENSIONS, IMAGE_MIMES, 5,
                     lambda ctx, ext: f"school-logo/{ctx['uid']}.{ext}"),
    'student-photos': (IMAGE_EXTENSIONS, IMAGE_MIMES, 5,
                        lambda ctx, ext: f"student-photos/{ctx.get('entity_id', 'pending')}/{ctx['uid']}.{ext}"),
    'teacher-photos': (IMAGE_EXTENSIONS, IMAGE_MIMES, 5,
                        lambda ctx, ext: f"teacher-photos/{ctx.get('entity_id', 'pending')}/{ctx['uid']}.{ext}"),
    'documents': (DOC_EXTENSIONS | IMAGE_EXTENSIONS, DOC_MIMES | IMAGE_MIMES, 20,
                  lambda ctx, ext: f"documents/{ctx['year']}/{ctx['month']}/{ctx['uid']}.{ext}"),
    'report-cards': ({'pdf'}, {'application/pdf'}, 20,
                      lambda ctx, ext: f"report-cards/{ctx['year']}/{ctx.get('term', 'Term')}/"
                                        f"{ctx.get('entity_id', 'unknown')}/{ctx['uid']}.{ext}"),
    'backups': ({'json', 'gz', 'zip'}, {'application/json', 'application/gzip', 'application/zip',
                                          'application/octet-stream'}, 200,
                lambda ctx, ext: f"backups/{ctx['year']}/{ctx['month']}/{ctx['ts']}-{ctx['uid']}.{ext}"),
    'imports': (DOC_EXTENSIONS, DOC_MIMES, 20,
                lambda ctx, ext: f"imports/{ctx['year']}/{ctx['month']}/{ctx['uid']}.{ext}"),
    'exports': (DOC_EXTENSIONS, DOC_MIMES, 50,
                lambda ctx, ext: f"exports/{ctx['year']}/{ctx['month']}/{ctx['uid']}.{ext}"),
    'inventory': (IMAGE_EXTENSIONS | DOC_EXTENSIONS, IMAGE_MIMES | DOC_MIMES, 15,
                  lambda ctx, ext: f"inventory/{ctx.get('entity_id', 'general')}/{ctx['uid']}.{ext}"),
    'other': (IMAGE_EXTENSIONS | DOC_EXTENSIONS, IMAGE_MIMES | DOC_MIMES, 15,
              lambda ctx, ext: f"other/{ctx['year']}/{ctx['month']}/{ctx['uid']}.{ext}"),
}


def build_object_key(category: str, filename: str, entity_id=None, term=None) -> tuple:
    """Validates + builds a safe, unique, unguessable object key. Never uses the
    original filename as (or inside) the key. Returns (object_key, ext)."""
    if category not in CATEGORIES:
        raise ValueError(f'Unknown upload category: {category}')
    allowed_ext, _allowed_mimes, _max_mb, key_fn = CATEGORIES[category]
    ext = (filename.rsplit('.', 1)[-1] if '.' in filename else '').lower()
    if ext in DANGEROUS_EXTENSIONS:
        raise ValueError('This file type is not allowed.')
    if ext not in allowed_ext:
        raise ValueError(f"File type '.{ext}' is not allowed for category '{category}'. "
                          f"Allowed: {', '.join(sorted(allowed_ext))}")
    now = datetime.utcnow()
    ctx = {
        'uid': uuid.uuid4().hex,
        'ts': int(time.time()),
        'year': now.strftime('%Y'),
        'month': now.strftime('%m'),
        'entity_id': secure_filename(str(entity_id)) if entity_id else None,
        'term': secure_filename(str(term)) if term else None,
    }
    key = key_fn(ctx, ext)
    return key, ext


def validate_upload(file_storage, category: str):
    """Runs extension + MIME + size checks BEFORE anything is sent to B2.
    Raises ValueError with a user-safe message on failure."""
    if category not in CATEGORIES:
        raise ValueError('Unknown upload category.')
    allowed_ext, allowed_mimes, max_mb, _ = CATEGORIES[category]
    filename = file_storage.filename or ''
    if not filename:
        raise ValueError('No file provided.')
    ext = (filename.rsplit('.', 1)[-1] if '.' in filename else '').lower()
    if ext in DANGEROUS_EXTENSIONS or ext not in allowed_ext:
        raise ValueError(f"File type '.{ext}' is not permitted for this upload.")
    mime = file_storage.mimetype or mimetypes.guess_type(filename)[0] or ''
    if mime not in allowed_mimes:
        raise ValueError(f"File content type '{mime}' is not permitted for this upload.")
    # Determine size without loading the whole file into memory.
    file_storage.stream.seek(0, os.SEEK_END)
    size = file_storage.stream.tell()
    file_storage.stream.seek(0)
    if size <= 0:
        raise ValueError('Uploaded file is empty.')
    if size > max_mb * 1024 * 1024:
        raise ValueError(f'File exceeds the {max_mb}MB limit for this upload type.')
    return size, mime


def b2_upload_fileobj(file_storage, object_key: str, content_type: str) -> str:
    """Streams the upload to B2 (does not fully buffer large files in memory) and
    returns a sha256 checksum computed while streaming."""
    hasher = hashlib.sha256()
    file_storage.stream.seek(0)

    class _HashingWrapper:
        """Wrap the incoming stream so boto3's chunked multipart uploader hashes
        each chunk as it goes, instead of us reading the whole file up front."""
        def __init__(self, inner):
            self._inner = inner
        def read(self, n=-1):
            chunk = self._inner.read(n)
            if chunk:
                hasher.update(chunk)
            return chunk
        def __getattr__(self, name):
            return getattr(self._inner, name)

    wrapped = _HashingWrapper(file_storage.stream)
    _b2_client.upload_fileobj(
        wrapped, B2_BUCKET_NAME, object_key,
        ExtraArgs={'ContentType': content_type or 'application/octet-stream'},
    )
    return hasher.hexdigest()


def b2_delete_object(object_key: str):
    """Bucket keeps all versions, so this adds a delete marker rather than
    permanently destroying history — acceptable for our soft-delete model,
    and it immediately stops the object resolving for ordinary access."""
    try:
        _b2_client.delete_object(Bucket=B2_BUCKET_NAME, Key=object_key)
    except (ClientError, BotoCoreError) as e:
        log.error('B2 delete_object failed for key=%s: %s', object_key, _redact(str(e)))
        raise


def b2_presigned_get_url(object_key: str, expires_in: int = None, download_name: str = None) -> str:
    params = {'Bucket': B2_BUCKET_NAME, 'Key': object_key}
    if download_name:
        params['ResponseContentDisposition'] = f'attachment; filename="{secure_filename(download_name)}"'
    return _b2_client.generate_presigned_url(
        'get_object', Params=params, ExpiresIn=expires_in or PRESIGNED_URL_EXPIRY_SECONDS,
    )


def b2_get_object_stream(object_key: str):
    return _b2_client.get_object(Bucket=B2_BUCKET_NAME, Key=object_key)


# ============================================================================
# 5. AUTH  (Flask-Login session cookie; passwords hashed server-side only)
# ============================================================================
ALL_ROLES = {
    'Administrator', 'Head Teacher', 'Deputy Head Teacher', 'Registrar',
    'Class Teacher', 'Subject Teacher', 'Bursar', 'Student', 'Parent',
}
STAFF_ROLES = ALL_ROLES - {'Student', 'Parent'}
PORTAL_ROLES = {'Student', 'Parent'}


class SessionUser(UserMixin):
    """Thin Flask-Login wrapper around a `users` Record row."""
    def __init__(self, record: Record):
        self.record = record

    def get_id(self):
        return self.record.id

    @property
    def role(self):
        return self.record.data.get('role')

    @property
    def name(self):
        return self.record.data.get('name')

    @property
    def linked_teacher_id(self):
        return self.record.data.get('linkedTeacherId')

    @property
    def linked_student_ids(self):
        return self.record.data.get('linkedStudentIds') or []


@login_manager.user_loader
def load_user(user_id):
    rec = Record.query.filter_by(store='users', id=user_id).first()
    if not rec or not rec.data.get('active', True):
        return None
    return SessionUser(rec)


@login_manager.unauthorized_handler
def unauthorized():
    return jsonify(success=False, error='Authentication required.'), 401


def strip_password(user_data: dict) -> dict:
    d = dict(user_data)
    d.pop('password', None)
    d['hasPassword'] = True
    return d


def public_user_json(rec: Record) -> dict:
    d = strip_password(rec.data)
    d['id'] = rec.id
    return d


LOCKOUT_THRESHOLD = 5
LOCKOUT_MINUTES = 15


@app.route('/api/auth/login', methods=['POST'])
@limiter.limit('10 per minute')
def api_login():
    body = request.get_json(silent=True) or {}
    username = (body.get('username') or '').strip().lower()
    role = body.get('role')
    password = body.get('password') or ''
    if not username or not role or not password:
        return jsonify(success=False, error='Username, role and password are required.'), 400
    if role not in ALL_ROLES:
        return jsonify(success=False, error='Unknown role.'), 400

    recs = Record.query.filter_by(store='users').all()
    rec = next((r for r in recs
                if (r.data.get('username') or '').strip().lower() == username
                and r.data.get('role') == role), None)
    if not rec:
        return jsonify(success=False, error='No account found for that role & username.'), 401

    u = dict(rec.data)
    locked_until = u.get('lockedUntil')
    if locked_until and time.time() * 1000 < locked_until:
        mins = math.ceil((locked_until - time.time() * 1000) / 60000)
        return jsonify(success=False, error=f'Account locked due to multiple failed attempts. '
                                             f'Try again in {mins} minute(s).', locked=True), 403
    if not u.get('active', True):
        return jsonify(success=False, error='This account has been deactivated. Contact the Administrator.'), 403

    stored_hash = u.get('password') or ''
    if not stored_hash or not check_password_hash(stored_hash, password):
        u['failedAttempts'] = int(u.get('failedAttempts') or 0) + 1
        if u['failedAttempts'] >= LOCKOUT_THRESHOLD:
            u['lockedUntil'] = (time.time() + LOCKOUT_MINUTES * 60) * 1000
            u['failedAttempts'] = 0
            _write_record('users', rec.id, u, actor_id=rec.id, actor_name=u.get('name'))
            return jsonify(success=False, error='Too many failed attempts. Account locked for '
                                                 f'{LOCKOUT_MINUTES} minutes.', locked=True), 403
        _write_record('users', rec.id, u, actor_id=rec.id, actor_name=u.get('name'))
        remaining = LOCKOUT_THRESHOLD - u['failedAttempts']
        return jsonify(success=False, error=f'Incorrect password. {remaining} attempt(s) remaining.'), 401

    u['failedAttempts'] = 0
    u['lockedUntil'] = None
    rec = _write_record('users', rec.id, u, actor_id=rec.id, actor_name=u.get('name'))

    session.clear()
    login_user(SessionUser(rec))
    session.permanent = True
    _log_activity(f"{u.get('name')} ({u.get('role')}) logged in.", actor_id=rec.id, actor_name=u.get('name'))
    return jsonify(success=True, user=public_user_json(rec))


@app.route('/api/auth/logout', methods=['POST'])
@login_required
def api_logout():
    _log_activity(f"{current_user.name} ({current_user.role}) logged out.",
                   actor_id=current_user.get_id(), actor_name=current_user.name)
    logout_user()
    session.clear()
    return jsonify(success=True)


@app.route('/api/auth/me')
@login_required
def api_me():
    return jsonify(success=True, user=public_user_json(current_user.record))


@app.route('/api/auth/change-password', methods=['POST'])
@login_required
@limiter.limit('10 per minute')
def api_change_password():
    body = request.get_json(silent=True) or {}
    current_pw = body.get('currentPassword') or ''
    new_pw = body.get('newPassword') or ''
    if len(new_pw) < 6:
        return jsonify(success=False, error='New password must be at least 6 characters.'), 400
    rec = Record.query.filter_by(store='users', id=current_user.get_id()).first()
    if not rec or not check_password_hash(rec.data.get('password') or '', current_pw):
        return jsonify(success=False, error='Current password is incorrect.'), 401
    u = dict(rec.data)
    u['password'] = generate_password_hash(new_pw)
    _write_record('users', rec.id, u, actor_id=current_user.get_id(), actor_name=current_user.name)
    _log_activity(f"{current_user.name} changed their password.",
                   actor_id=current_user.get_id(), actor_name=current_user.name)
    return jsonify(success=True)


# ============================================================================
# 6. STORE-LEVEL + ROW-LEVEL PERMISSIONS
# ============================================================================
# Administrator is always a superuser and bypasses this table entirely.
# Coverage below mirrors the frontend's own ROLE_MODULES map. Row-level
# `scope_field` restricts Student/Parent roles to only rows whose named
# field matches one of their own linkedStudentIds — staff roles always see
# every row of a store they can read (finer per-class staff scoping is
# already enforced inside the existing frontend UI logic and can be layered
# in here incrementally as `scope_field` rules per role if you need it
# enforced server-side too).
STORE_ACCESS = {
    'users':               {'read': set(),                                            'write': set()},
    'students':            {'read': STAFF_ROLES | PORTAL_ROLES,                        'write': {'Head Teacher', 'Registrar', 'Class Teacher'}},
    'teachers':             {'read': STAFF_ROLES,                                      'write': set()},
    'classes':              {'read': STAFF_ROLES | PORTAL_ROLES,                       'write': set()},
    'subjects':             {'read': STAFF_ROLES | PORTAL_ROLES,                       'write': set()},
    'exams':                {'read': STAFF_ROLES | PORTAL_ROLES,                       'write': {'Head Teacher', 'Deputy Head Teacher'}},
    'marks':                {'read': STAFF_ROLES | PORTAL_ROLES, 'scope_field': 'studentId',
                              'write': {'Head Teacher', 'Class Teacher', 'Subject Teacher'}},
    'attendance':           {'read': {'Head Teacher', 'Deputy Head Teacher', 'Class Teacher'} | PORTAL_ROLES,
                              'scope_field': 'studentId', 'write': {'Class Teacher', 'Deputy Head Teacher'}},
    'feeStructures':        {'read': STAFF_ROLES | PORTAL_ROLES,                       'write': {'Bursar'}},
    'feePayments':          {'read': {'Bursar', 'Head Teacher', 'Class Teacher'} | PORTAL_ROLES,
                              'scope_field': 'studentId', 'write': {'Bursar'}},
    'grading':              {'read': STAFF_ROLES | PORTAL_ROLES,                       'write': {'Head Teacher'}},
    'cbcGrading':           {'read': STAFF_ROLES | PORTAL_ROLES,                       'write': {'Head Teacher'}},
    'announcements':        {'read': STAFF_ROLES | PORTAL_ROLES,
                              'write': {'Head Teacher', 'Deputy Head Teacher', 'Class Teacher', 'Registrar', 'Bursar'}},
    'books':                {'read': {'Bursar'} | PORTAL_ROLES,                        'write': {'Bursar'}},
    'borrows':               {'read': {'Bursar'} | PORTAL_ROLES, 'scope_field': 'studentId', 'write': {'Bursar'}},
    'timetable':             {'read': STAFF_ROLES | PORTAL_ROLES,                      'write': {'Head Teacher'}},
    'timetableRules':        {'read': STAFF_ROLES,                                     'write': {'Head Teacher'}},
    'settings':              {'read': STAFF_ROLES | PORTAL_ROLES,                      'write': set()},
    'activity':              {'read': {'Head Teacher', 'Deputy Head Teacher'}, 'write': STAFF_ROLES | PORTAL_ROLES,
                               'immutable': True},
    'discipline':            {'read': {'Head Teacher', 'Deputy Head Teacher', 'Class Teacher'} | PORTAL_ROLES,
                               'scope_field': 'studentId', 'write': {'Deputy Head Teacher', 'Class Teacher'}},
    'inventoryItems':        {'read': {'Bursar'},                                      'write': {'Bursar'}},
    'suppliers':             {'read': {'Bursar'},                                      'write': {'Bursar'}},
    'stockMovements':        {'read': {'Bursar'},                                      'write': {'Bursar'}},
    'assets':                {'read': {'Bursar'},                                      'write': {'Bursar'}},
    'leaveRequests':         {'read': set(),                                           'write': set()},
    'payrollRecords':        {'read': set(),                                           'write': set()},
    'appraisals':            {'read': set(),                                           'write': set()},
    'staffDocuments':        {'read': set(),                                           'write': set()},
    'leaveOuts':             {'read': {'Head Teacher', 'Deputy Head Teacher', 'Registrar', 'Class Teacher'} | PORTAL_ROLES,
                               'scope_field': 'studentId', 'write': {'Deputy Head Teacher', 'Registrar', 'Class Teacher'}},
    'teachingAssignments':   {'read': STAFF_ROLES,                                     'write': set()},
}
# Any store not explicitly listed above defaults to Administrator-only, both
# read and write — a safe default for anything added later.


def _role_can(store: str, role: str, action: str) -> bool:
    if role == 'Administrator':
        return True
    cfg = STORE_ACCESS.get(store)
    if not cfg:
        return False
    allowed = cfg.get(action, set())
    return allowed == '*' or role in allowed


def _allowed_student_ids() -> set:
    if current_user.role not in PORTAL_ROLES:
        return set()
    return set(current_user.linked_student_ids)


def _scope_rows(store: str, rows: list) -> list:
    """Applies row-level filtering for Student/Parent roles on stores that
    carry a scope_field (e.g. only their own marks/attendance/fee rows)."""
    cfg = STORE_ACCESS.get(store, {})
    scope_field = cfg.get('scope_field')
    if current_user.role == 'Administrator' or current_user.role in STAFF_ROLES or not scope_field:
        return rows
    allowed_ids = _allowed_student_ids()
    return [r for r in rows if r.get(scope_field) in allowed_ids]


def _row_visible(store: str, row: dict) -> bool:
    cfg = STORE_ACCESS.get(store, {})
    scope_field = cfg.get('scope_field')
    if current_user.role == 'Administrator' or current_user.role in STAFF_ROLES or not scope_field:
        return True
    return row.get(scope_field) in _allowed_student_ids()


def require_role(*roles):
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrapper(*a, **kw):
            if current_user.role != 'Administrator' and current_user.role not in roles:
                return jsonify(success=False, error='You do not have permission to perform this action.'), 403
            return fn(*a, **kw)
        return wrapper
    return deco


# ============================================================================
# 7. RECORD (generic data store) HELPERS
# ============================================================================
def _sanitize_write(store: str, data: dict) -> dict:
    """Server-side field sanitization applied to every write, regardless of
    what the client sent — closes off the most common tamper vectors."""
    data = dict(data)
    if store == 'users':
        pw = data.get('password')
        # Only ever accept a plaintext password here and hash it ourselves.
        # If the field is missing/empty, the caller is not changing it —
        # merged back onto the existing hash by _write_record's caller.
        if pw:
            data['password'] = generate_password_hash(pw)
        data.pop('failedAttempts', None) if False else None  # (kept intentionally permissive: login flow manages this)
    if store == 'activity':
        # Prevent spoofing who performed an action / when.
        data['user'] = current_user.name if current_user.is_authenticated else data.get('user', 'System')
        data['time'] = datetime.now(timezone.utc).isoformat()
    return data


def _write_record(store: str, rec_id: str, data: dict, actor_id=None, actor_name=None) -> Record:
    rec = Record.query.filter_by(store=store, id=rec_id).first()
    if rec is None:
        rec = Record(store=store, id=rec_id, data=data, updated_by=actor_id)
        db.session.add(rec)
    else:
        rec.data = data
        rec.updated_by = actor_id
    db.session.commit()
    return rec


def _log_activity(text_msg: str, actor_id=None, actor_name=None):
    entry = {
        'id': 'act_' + uuid.uuid4().hex[:12],
        'text': text_msg,
        'user': actor_name or 'System',
        'time': datetime.now(timezone.utc).isoformat(),
    }
    rec = Record(store='activity', id=entry['id'], data=entry, updated_by=actor_id)
    db.session.add(rec)
    db.session.commit()


# Field names, per store, that hold a FileMeta id and should be resolved to a
# same-origin, cookie-authenticated `/api/files/<id>/stream` URL when a
# record is serialized for API responses (so the existing frontend, which
# just does `<img src="${student.photo}">`, keeps working unmodified).
FILE_REF_FIELDS = {
    'students': ['photo'],
    'teachers': ['photo'],
    'users': ['photo'],
    'settings': ['logoDataUrl'],
    'staffDocuments': ['fileId'],
}


def _resolve_file_refs(store: str, row: dict) -> dict:
    fields = FILE_REF_FIELDS.get(store)
    if not fields:
        return row
    row = dict(row)
    for f in fields:
        val = row.get(f)
        if val and isinstance(val, str) and not val.startswith('/api/') and not val.startswith('http') \
                and not val.startswith('data:'):
            row[f] = f'/api/files/{val}/stream'
    return row


def _serialize_row(store: str, row: dict) -> dict:
    row = _resolve_file_refs(store, row)
    if store == 'users':
        row = strip_password(row)
    return row


# ============================================================================
# 8. GENERIC DATA API  (mirrors the frontend's old IndexedDB calls 1:1)
# ============================================================================
@app.route('/api/data/bootstrap')
@login_required
def api_bootstrap():
    """Everything the current role is allowed to read, in one round trip —
    replaces the old idb.open()+loadAll() startup sequence."""
    out = {}
    for store in STORE_NAMES:
        if not _role_can(store, current_user.role, 'read'):
            out[store] = []
            continue
        rows = [r.data for r in Record.query.filter_by(store=store).all()]
        rows = _scope_rows(store, rows)
        out[store] = [_serialize_row(store, r) for r in rows]
    return jsonify(success=True, data=out)


@app.route('/api/data/<store>', methods=['GET'])
@login_required
def api_list(store):
    if store not in STORE_NAMES:
        return jsonify(success=False, error='Unknown store.'), 404
    if not _role_can(store, current_user.role, 'read'):
        return jsonify(success=False, error='You do not have permission to view this data.'), 403
    rows = [r.data for r in Record.query.filter_by(store=store).all()]
    rows = _scope_rows(store, rows)
    return jsonify(success=True, data=[_serialize_row(store, r) for r in rows])


@app.route('/api/data/<store>/<rec_id>', methods=['GET'])
@login_required
def api_get(store, rec_id):
    if store not in STORE_NAMES:
        return jsonify(success=False, error='Unknown store.'), 404
    if not _role_can(store, current_user.role, 'read'):
        return jsonify(success=False, error='You do not have permission to view this data.'), 403
    rec = Record.query.filter_by(store=store, id=rec_id).first()
    if not rec or not _row_visible(store, rec.data):
        return jsonify(success=False, error='Not found.'), 404
    return jsonify(success=True, data=_serialize_row(store, rec.data))


@app.route('/api/data/<store>/<rec_id>', methods=['PUT'])
@login_required
@limiter.limit('300 per minute')
def api_upsert(store, rec_id):
    if store not in STORE_NAMES:
        return jsonify(success=False, error='Unknown store.'), 404
    if not _role_can(store, current_user.role, 'write'):
        return jsonify(success=False, error='You do not have permission to modify this data.'), 403
    cfg = STORE_ACCESS.get(store, {})
    existing = Record.query.filter_by(store=store, id=rec_id).first()
    if cfg.get('immutable') and existing:
        return jsonify(success=False, error='This record cannot be modified once created.'), 403

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(success=False, error='Request body must be a JSON object.'), 400
    if body.get('id') and body['id'] != rec_id:
        return jsonify(success=False, error='Body id does not match URL id.'), 400
    body['id'] = rec_id

    if store == 'users':
        # A user editing/creating another login must not be able to blank out
        # or silently keep a password they don't know: if no new password is
        # given, preserve whatever hash already exists.
        if not body.get('password') and existing:
            body['password'] = existing.data.get('password')
        elif not body.get('password') and not existing:
            return jsonify(success=False, error='A password is required to create a new login.'), 400

    body = _sanitize_write(store, body)
    rec = _write_record(store, rec_id, body, actor_id=current_user.get_id(), actor_name=current_user.name)
    return jsonify(success=True, data=_serialize_row(store, rec.data))


@app.route('/api/data/<store>/<rec_id>', methods=['DELETE'])
@login_required
def api_delete(store, rec_id):
    if store not in STORE_NAMES:
        return jsonify(success=False, error='Unknown store.'), 404
    cfg = STORE_ACCESS.get(store, {})
    if cfg.get('immutable') and current_user.role != 'Administrator':
        return jsonify(success=False, error='This record cannot be deleted.'), 403
    if not _role_can(store, current_user.role, 'write'):
        return jsonify(success=False, error='You do not have permission to delete this data.'), 403
    rec = Record.query.filter_by(store=store, id=rec_id).first()
    if rec:
        db.session.delete(rec)
        db.session.commit()
    return jsonify(success=True)


# ============================================================================
# 9. FILE UPLOAD / DOWNLOAD API
# ============================================================================
def _category_permission_ok(category: str, action: str, entity_id=None) -> bool:
    """Coarse category-level gate, checked BEFORE any B2 call. Row-level
    ownership (e.g. 'is this really your child's document') is additionally
    checked in _can_access_file for reads."""
    role = current_user.role
    if role == 'Administrator':
        return True
    if category == 'backups':
        return False  # Administrator only, no exceptions.
    if category in ('imports', 'exports'):
        return role in {'Head Teacher', 'Bursar'}
    if category == 'inventory':
        return role in {'Bursar'}
    if category in ('school-logo',):
        return action == 'read'  # everyone may view the logo; only Administrator may replace it
    if category in ('student-photos',):
        return role in STAFF_ROLES if action == 'write' else True
    if category in ('teacher-photos',):
        return role in STAFF_ROLES if action == 'write' else True
    if category in ('documents', 'report-cards'):
        return True  # further narrowed per-file by _can_access_file
    return role in STAFF_ROLES


def _can_access_file(fm: FileMeta) -> bool:
    role = current_user.role
    if role == 'Administrator':
        return True
    if fm.category == 'backups':
        return False
    if fm.category in ('imports', 'exports'):
        return role in {'Head Teacher', 'Bursar'}
    if fm.category == 'inventory':
        return role in {'Bursar'}
    if fm.category in ('school-logo', 'teacher-photos'):
        return True  # low-sensitivity, viewable by any authenticated user
    if fm.category == 'student-photos':
        if role in STAFF_ROLES:
            return True
        return fm.related_entity_id in _allowed_student_ids()
    if fm.category in ('documents', 'report-cards'):
        if role in STAFF_ROLES:
            return True
        if fm.related_entity_type == 'student':
            return fm.related_entity_id in _allowed_student_ids()
        return False
    return role in STAFF_ROLES


@app.route('/api/files/upload', methods=['POST'])
@login_required
@limiter.limit('60 per minute')
def api_files_upload():
    category = request.form.get('category', 'other')
    entity_type = request.form.get('relatedEntityType')
    entity_id = request.form.get('relatedEntityId')
    term = request.form.get('term')
    file_storage = request.files.get('file')

    if not file_storage:
        return jsonify(success=False, error='No file provided.'), 400
    if not _category_permission_ok(category, 'write', entity_id):
        return jsonify(success=False, error='You do not have permission to upload this type of file.'), 403
    if not b2_configured():
        return jsonify(success=False, error='File storage is not configured on the server.'), 503

    try:
        size, mime = validate_upload(file_storage, category)
        object_key, ext = build_object_key(category, file_storage.filename, entity_id=entity_id, term=term)
    except ValueError as e:
        return jsonify(success=False, error=str(e)), 400

    safe_original = secure_filename(file_storage.filename)[:500] or f'file.{ext}'
    file_id = uuid.uuid4().hex

    try:
        checksum = b2_upload_fileobj(file_storage, object_key, mime)
    except (ClientError, BotoCoreError) as e:
        log.error('B2 upload failed: %s', _redact(str(e)))
        return jsonify(success=False, error='Upload to storage failed. Please try again.'), 502

    fm = FileMeta(
        id=file_id, original_filename=safe_original, stored_filename=object_key.rsplit('/', 1)[-1],
        object_key=object_key, bucket_name=B2_BUCKET_NAME, content_type=mime, file_size=size,
        checksum=checksum, category=category, uploaded_by=current_user.get_id(),
        related_entity_type=entity_type, related_entity_id=entity_id,
    )
    try:
        db.session.add(fm)
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        log.error('DB commit failed after B2 upload — cleaning up orphaned object %s: %s',
                   object_key, _redact(str(e)))
        try:
            b2_delete_object(object_key)
        except Exception:
            log.error('Failed to clean up orphaned B2 object %s — manual cleanup needed.', object_key)
        return jsonify(success=False, error='Could not save file metadata. Please try again.'), 500

    _log_activity(f"{current_user.name} uploaded a file ({category}): {safe_original}",
                   actor_id=current_user.get_id(), actor_name=current_user.name)
    return jsonify(success=True, file=fm.public_json())


@app.route('/api/files/<file_id>', methods=['GET'])
@login_required
def api_file_meta(file_id):
    fm = FileMeta.query.filter_by(id=file_id, deleted_at=None).first()
    if not fm or not _can_access_file(fm):
        return jsonify(success=False, error='Not found.'), 404
    return jsonify(success=True, file=fm.public_json())


@app.route('/api/files/<file_id>/download', methods=['GET'])
@login_required
def api_file_download(file_id):
    """Returns a short-lived presigned URL — generated only AFTER the
    permission check, never persisted."""
    fm = FileMeta.query.filter_by(id=file_id, deleted_at=None).first()
    if not fm or not _can_access_file(fm):
        return jsonify(success=False, error='Not found.'), 404
    try:
        url = b2_presigned_get_url(fm.object_key, download_name=fm.original_filename)
    except (ClientError, BotoCoreError) as e:
        log.error('Presign failed for file %s: %s', file_id, _redact(str(e)))
        return jsonify(success=False, error='Could not generate a download link. Please try again.'), 502
    return jsonify(success=True, url=url, expiresIn=PRESIGNED_URL_EXPIRY_SECONDS)


@app.route('/api/files/<file_id>/stream', methods=['GET'])
@login_required
def api_file_stream(file_id):
    """Proxies the file bytes through this server. Used for inline <img>
    tags (browsers already send the session cookie automatically) so the
    frontend doesn't need to juggle presigned-URL expiry for everyday
    photo/logo rendering."""
    fm = FileMeta.query.filter_by(id=file_id, deleted_at=None).first()
    if not fm or not _can_access_file(fm):
        abort(404)
    try:
        obj = b2_get_object_stream(fm.object_key)
    except (ClientError, BotoCoreError) as e:
        log.error('B2 stream fetch failed for file %s: %s', file_id, _redact(str(e)))
        abort(502)
    body = obj['Body']

    def generate():
        try:
            while True:
                chunk = body.read(65536)
                if not chunk:
                    break
                yield chunk
        finally:
            body.close()

    resp = Response(stream_with_context(generate()), mimetype=fm.content_type or 'application/octet-stream')
    resp.headers['Cache-Control'] = 'private, max-age=60'
    resp.headers['Content-Disposition'] = f'inline; filename="{secure_filename(fm.original_filename)}"'
    if fm.file_size:
        resp.headers['Content-Length'] = str(fm.file_size)
    return resp


@app.route('/api/files/<file_id>', methods=['DELETE'])
@login_required
def api_file_delete(file_id):
    fm = FileMeta.query.filter_by(id=file_id, deleted_at=None).first()
    if not fm:
        return jsonify(success=False, error='Not found.'), 404
    if current_user.role != 'Administrator' and not _category_permission_ok(fm.category, 'write',
                                                                              fm.related_entity_id):
        return jsonify(success=False, error='You do not have permission to delete this file.'), 403

    fm.deleted_at = datetime.now(timezone.utc)
    try:
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        log.error('DB update failed while deleting file %s: %s', file_id, _redact(str(e)))
        return jsonify(success=False, error='Could not delete file metadata.'), 500

    # DB marked deleted first; only now touch B2 (keeps old versions per bucket policy).
    try:
        b2_delete_object(fm.object_key)
    except Exception:
        log.error('B2 object delete failed for %s (metadata already marked deleted).', fm.object_key)

    _log_activity(f"{current_user.name} deleted a file: {fm.original_filename}",
                   actor_id=current_user.get_id(), actor_name=current_user.name)
    return jsonify(success=True)


# ---- Convenience, purpose-specific upload endpoints ------------------------
def _handle_entity_photo_upload(category, entity_store, entity_id, photo_field='photo'):
    file_storage = request.files.get('file')
    if not file_storage:
        return jsonify(success=False, error='No file provided.'), 400
    rec = Record.query.filter_by(store=entity_store, id=entity_id).first()
    if not rec:
        return jsonify(success=False, error='Record not found.'), 404
    if not _role_can(entity_store, current_user.role, 'write') and current_user.role != 'Administrator':
        return jsonify(success=False, error='You do not have permission to update this photo.'), 403
    if not b2_configured():
        return jsonify(success=False, error='File storage is not configured on the server.'), 503
    try:
        size, mime = validate_upload(file_storage, category)
        object_key, ext = build_object_key(category, file_storage.filename, entity_id=entity_id)
    except ValueError as e:
        return jsonify(success=False, error=str(e)), 400

    file_id = uuid.uuid4().hex
    try:
        checksum = b2_upload_fileobj(file_storage, object_key, mime)
    except (ClientError, BotoCoreError) as e:
        log.error('B2 upload failed: %s', _redact(str(e)))
        return jsonify(success=False, error='Upload to storage failed.'), 502

    fm = FileMeta(id=file_id, original_filename=secure_filename(file_storage.filename) or f'photo.{ext}',
                  stored_filename=object_key.rsplit('/', 1)[-1], object_key=object_key,
                  bucket_name=B2_BUCKET_NAME, content_type=mime, file_size=size, checksum=checksum,
                  category=category, uploaded_by=current_user.get_id(),
                  related_entity_type=entity_store[:-1] if entity_store.endswith('s') else entity_store,
                  related_entity_id=entity_id)
    old_file_id = rec.data.get(photo_field)
    data = dict(rec.data)
    data[photo_field] = file_id
    try:
        db.session.add(fm)
        rec.data = data
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        log.error('DB commit failed after photo upload — cleaning up orphaned object %s: %s',
                   object_key, _redact(str(e)))
        try:
            b2_delete_object(object_key)
        except Exception:
            pass
        return jsonify(success=False, error='Could not save photo. Please try again.'), 500

    # Best-effort cleanup of the previous photo, if any and if it looks like one of ours.
    if old_file_id and isinstance(old_file_id, str) and not old_file_id.startswith(('http', 'data:')):
        old_fm = FileMeta.query.filter_by(id=old_file_id, deleted_at=None).first()
        if old_fm:
            old_fm.deleted_at = datetime.now(timezone.utc)
            db.session.commit()
            try:
                b2_delete_object(old_fm.object_key)
            except Exception:
                pass

    return jsonify(success=True, file=fm.public_json(), fileId=file_id)


@app.route('/api/students/<student_id>/photo', methods=['POST'])
@login_required
def api_student_photo(student_id):
    return _handle_entity_photo_upload('student-photos', 'students', student_id)


@app.route('/api/teachers/<teacher_id>/photo', methods=['POST'])
@login_required
def api_teacher_photo(teacher_id):
    return _handle_entity_photo_upload('teacher-photos', 'teachers', teacher_id)


@app.route('/api/settings/logo', methods=['POST'])
@require_role('Administrator')
def api_settings_logo():
    return _handle_entity_photo_upload('school-logo', 'settings', 'school', photo_field='logoDataUrl')


@app.route('/api/documents/upload', methods=['POST'])
@login_required
def api_documents_upload():
    """Backs the Document Center (staffDocuments store): uploads the file to
    B2 and returns a fileId — the frontend then saves that id onto the
    staffDocuments record instead of an inline base64 blob."""
    file_storage = request.files.get('file')
    entity_id = request.form.get('relatedEntityId')
    if not file_storage:
        return jsonify(success=False, error='No file provided.'), 400
    if not b2_configured():
        return jsonify(success=False, error='File storage is not configured on the server.'), 503
    try:
        size, mime = validate_upload(file_storage, 'documents')
        object_key, ext = build_object_key('documents', file_storage.filename, entity_id=entity_id)
    except ValueError as e:
        return jsonify(success=False, error=str(e)), 400

    file_id = uuid.uuid4().hex
    try:
        checksum = b2_upload_fileobj(file_storage, object_key, mime)
    except (ClientError, BotoCoreError) as e:
        log.error('B2 upload failed: %s', _redact(str(e)))
        return jsonify(success=False, error='Upload to storage failed.'), 502

    fm = FileMeta(id=file_id, original_filename=secure_filename(file_storage.filename) or f'document.{ext}',
                  stored_filename=object_key.rsplit('/', 1)[-1], object_key=object_key,
                  bucket_name=B2_BUCKET_NAME, content_type=mime, file_size=size, checksum=checksum,
                  category='documents', uploaded_by=current_user.get_id(),
                  related_entity_type='teacher', related_entity_id=entity_id)
    try:
        db.session.add(fm)
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        try:
            b2_delete_object(object_key)
        except Exception:
            pass
        return jsonify(success=False, error='Could not save document metadata.'), 500

    return jsonify(success=True, file=fm.public_json(), fileId=file_id)


# ============================================================================
# 10. BACKUPS  (Administrator only)
# ============================================================================
@app.route('/api/backups', methods=['POST'])
@require_role('Administrator')
@limiter.limit('5 per hour')
def api_create_backup():
    dump = {store: [r.data for r in Record.query.filter_by(store=store).all()] for store in STORE_NAMES}
    payload = json.dumps({'createdAt': datetime.now(timezone.utc).isoformat(), 'stores': dump}).encode('utf-8')

    now = datetime.utcnow()
    object_key = f"backups/{now.strftime('%Y')}/{now.strftime('%m')}/{int(time.time())}-{uuid.uuid4().hex}.json"
    checksum = hashlib.sha256(payload).hexdigest()
    if not b2_configured():
        return jsonify(success=False, error='File storage is not configured on the server.'), 503
    try:
        _b2_client.put_object(Bucket=B2_BUCKET_NAME, Key=object_key, Body=payload, ContentType='application/json')
    except (ClientError, BotoCoreError) as e:
        log.error('Backup upload failed: %s', _redact(str(e)))
        return jsonify(success=False, error='Backup upload failed.'), 502

    file_id = uuid.uuid4().hex
    fm = FileMeta(id=file_id, original_filename=f'backup-{now.strftime("%Y%m%d-%H%M%S")}.json',
                  stored_filename=object_key.rsplit('/', 1)[-1], object_key=object_key,
                  bucket_name=B2_BUCKET_NAME, content_type='application/json', file_size=len(payload),
                  checksum=checksum, category='backups', uploaded_by=current_user.get_id())
    db.session.add(fm)
    db.session.commit()
    _log_activity(f"{current_user.name} created a full system backup.",
                   actor_id=current_user.get_id(), actor_name=current_user.name)
    return jsonify(success=True, file=fm.public_json())


@app.route('/api/backups', methods=['GET'])
@require_role('Administrator')
def api_list_backups():
    rows = FileMeta.query.filter_by(category='backups', deleted_at=None).order_by(FileMeta.created_at.desc()).all()
    return jsonify(success=True, data=[r.public_json() for r in rows])


@app.route('/api/backups/<file_id>/restore', methods=['POST'])
@require_role('Administrator')
@limiter.limit('3 per hour')
def api_restore_backup(file_id):
    body = request.get_json(silent=True) or {}
    if body.get('confirm') != 'RESTORE':
        return jsonify(success=False, error='Restore requires {"confirm": "RESTORE"} in the request body.'), 400

    fm = FileMeta.query.filter_by(id=file_id, category='backups', deleted_at=None).first()
    if not fm:
        return jsonify(success=False, error='Backup not found.'), 404

    try:
        obj = b2_get_object_stream(fm.object_key)
        payload = json.loads(obj['Body'].read())
    except Exception as e:
        log.error('Failed to read backup %s for restore: %s', file_id, _redact(str(e)))
        return jsonify(success=False, error='Could not read the backup file.'), 502

    stores = payload.get('stores')
    if not isinstance(stores, dict):
        return jsonify(success=False, error='Backup file has an unrecognized/incompatible format.'), 400
    unknown = [s for s in stores if s not in STORE_NAMES]
    if unknown:
        return jsonify(success=False, error=f'Backup references unknown store(s): {unknown}. '
                                             f'It may be from an incompatible version.'), 400

    # Safety backup of current state before we overwrite anything.
    safety_dump = {store: [r.data for r in Record.query.filter_by(store=store).all()] for store in STORE_NAMES}
    safety_payload = json.dumps({'createdAt': datetime.now(timezone.utc).isoformat(),
                                  'note': f'auto safety backup before restoring {file_id}',
                                  'stores': safety_dump}).encode('utf-8')
    now = datetime.utcnow()
    safety_key = f"backups/{now.strftime('%Y')}/{now.strftime('%m')}/{int(time.time())}-safety-{uuid.uuid4().hex}.json"
    try:
        _b2_client.put_object(Bucket=B2_BUCKET_NAME, Key=safety_key, Body=safety_payload,
                               ContentType='application/json')
        safety_fm = FileMeta(id=uuid.uuid4().hex, original_filename=f'safety-backup-{now.strftime("%Y%m%d-%H%M%S")}.json',
                              stored_filename=safety_key.rsplit('/', 1)[-1], object_key=safety_key,
                              bucket_name=B2_BUCKET_NAME, content_type='application/json',
                              file_size=len(safety_payload), checksum=hashlib.sha256(safety_payload).hexdigest(),
                              category='backups', uploaded_by=current_user.get_id())
        db.session.add(safety_fm)
        db.session.commit()
    except Exception as e:
        log.error('Could not create pre-restore safety backup, aborting restore: %s', _redact(str(e)))
        return jsonify(success=False, error='Could not create a safety backup before restoring — '
                                             'restore aborted to avoid data loss.'), 500

    try:
        for store, rows in stores.items():
            Record.query.filter_by(store=store).delete()
            for row in rows:
                if not isinstance(row, dict) or not row.get('id'):
                    continue
                db.session.add(Record(store=store, id=row['id'], data=row, updated_by=current_user.get_id()))
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        log.error('Restore transaction failed, rolled back: %s', _redact(str(e)))
        return jsonify(success=False, error='Restore failed and was rolled back. No data was changed.'), 500

    _log_activity(f"{current_user.name} restored the system from backup {fm.original_filename}.",
                   actor_id=current_user.get_id(), actor_name=current_user.name)
    return jsonify(success=True)


# ============================================================================
# 11. HEALTH CHECK
# ============================================================================
_last_b2_check = {'ts': 0, 'ok': False}


@app.route('/api/health')
def api_health():
    db_ok = False
    try:
        db.session.execute(text('SELECT 1'))
        db_ok = True
    except Exception as e:
        log.error('Health check DB failure: %s', _redact(str(e)))

    # Cache the B2 reachability probe briefly — don't hammer B2 on every health check.
    now = time.time()
    if now - _last_b2_check['ts'] > 30:
        b2_ok = False
        if b2_configured():
            try:
                _b2_client.head_bucket(Bucket=B2_BUCKET_NAME)
                b2_ok = True
            except Exception as e:
                log.error('Health check B2 failure: %s', _redact(str(e)))
        _last_b2_check.update(ts=now, ok=b2_ok)
    b2_ok = _last_b2_check['ok']

    status = 'healthy' if (db_ok and b2_ok) else 'degraded'
    return jsonify(success=True, status=status,
                    database='connected' if db_ok else 'unavailable',
                    storage='configured' if b2_ok else 'unavailable'), (200 if status == 'healthy' else 503)


# ============================================================================
# 12. ERROR HANDLERS  (never leak secrets/internals)
# ============================================================================
@app.errorhandler(413)
def too_large(e):
    return jsonify(success=False, error='File too large.'), 413


@app.errorhandler(404)
def not_found(e):
    return jsonify(success=False, error='Not found.'), 404


@app.errorhandler(429)
def rate_limited(e):
    return jsonify(success=False, error='Too many requests. Please slow down and try again shortly.'), 429


@app.errorhandler(500)
def server_error(e):
    log.error('Unhandled server error: %s', _redact(str(e)))
    return jsonify(success=False, error='An unexpected error occurred. Please try again.'), 500


# ============================================================================
# 13. FIRST-RUN SEEDING
# ============================================================================
DEFAULT_GRADING_SCALE = [
    {'grade': 'A', 'min': 80, 'max': 100, 'points': 12, 'remark': 'Excellent'},
    {'grade': 'A-', 'min': 75, 'max': 79, 'points': 11, 'remark': 'Very Good'},
    {'grade': 'B+', 'min': 70, 'max': 74, 'points': 10, 'remark': 'Good'},
    {'grade': 'B', 'min': 65, 'max': 69, 'points': 9, 'remark': 'Good'},
    {'grade': 'B-', 'min': 60, 'max': 64, 'points': 8, 'remark': 'Above Average'},
    {'grade': 'C+', 'min': 55, 'max': 59, 'points': 7, 'remark': 'Average'},
    {'grade': 'C', 'min': 50, 'max': 54, 'points': 6, 'remark': 'Average'},
    {'grade': 'C-', 'min': 45, 'max': 49, 'points': 5, 'remark': 'Below Average'},
    {'grade': 'D+', 'min': 40, 'max': 44, 'points': 4, 'remark': 'Weak'},
    {'grade': 'D', 'min': 35, 'max': 39, 'points': 3, 'remark': 'Weak'},
    {'grade': 'D-', 'min': 30, 'max': 34, 'points': 2, 'remark': 'Poor'},
    {'grade': 'E', 'min': 0, 'max': 29, 'points': 1, 'remark': 'Very Poor'},
]
DEFAULT_CBC_SCALE = [
    {'grade': 'EE', 'min': 75, 'max': 100, 'points': 7, 'remark': 'Exceeding Expectation'},
    {'grade': 'ME2', 'min': 65, 'max': 74, 'points': 6, 'remark': 'Meeting Expectation (Upper)'},
    {'grade': 'ME1', 'min': 50, 'max': 64, 'points': 5, 'remark': 'Meeting Expectation'},
    {'grade': 'AE2', 'min': 40, 'max': 49, 'points': 4, 'remark': 'Approaching Expectation (Upper)'},
    {'grade': 'AE1', 'min': 25, 'max': 39, 'points': 3, 'remark': 'Approaching Expectation'},
    {'grade': 'BE2', 'min': 15, 'max': 24, 'points': 2, 'remark': 'Below Expectation (Upper)'},
    {'grade': 'BE1', 'min': 0, 'max': 14, 'points': 1, 'remark': 'Below Expectation'},
]


def seed_if_empty():
    if Record.query.filter_by(store='users').first() is None:
        username = os.environ.get('ADMIN_DEFAULT_USERNAME', 'admin')
        password = os.environ.get('ADMIN_DEFAULT_PASSWORD')
        generated = False
        if not password:
            password = secrets.token_urlsafe(12)
            generated = True
        admin = {
            'id': 'u_' + uuid.uuid4().hex[:12], 'username': username,
            'password': generate_password_hash(password), 'role': 'Administrator',
            'name': 'System Administrator', 'photo': '', 'active': True,
            'failedAttempts': 0, 'lockedUntil': None, 'mustChange': generated,
        }
        db.session.add(Record(store='users', id=admin['id'], data=admin))
        db.session.commit()
        if generated:
            log.warning('=' * 70)
            log.warning('FIRST RUN: created default Administrator account.')
            log.warning('  username: %s', username)
            log.warning('  password: %s', password)
            log.warning('CHANGE THIS PASSWORD IMMEDIATELY — it will not be shown again.')
            log.warning('=' * 70)

    if Record.query.filter_by(store='grading').first() is None:
        for g in DEFAULT_GRADING_SCALE:
            rid = 'gr_' + uuid.uuid4().hex[:12]
            db.session.add(Record(store='grading', id=rid, data={**g, 'id': rid}))
        db.session.commit()

    if Record.query.filter_by(store='cbcGrading').first() is None:
        for g in DEFAULT_CBC_SCALE:
            rid = 'cbc_' + uuid.uuid4().hex[:12]
            db.session.add(Record(store='cbcGrading', id=rid, data={**g, 'id': rid}))
        db.session.commit()

    if Record.query.filter_by(store='settings', id='school').first() is None:
        settings = {
            'id': 'school', 'schoolName': "ARNESEN'S COMPREHENSIVE SCHOOL",
            'motto': 'Discipline and Hardwork for success',
            'address': 'P.O. Box 1024–00100, Nairobi, Kenya',
            'phone': '+254 700 000 000', 'email': 'info@arnesenscomprehensive.sc.ke',
            'currentYear': str(datetime.now().year), 'currentTerm': 'Term 1',
            'autoLogoutMin': 20, 'logoDataUrl': '', 'gradingSystem': '844',
        }
        db.session.add(Record(store='settings', id='school', data=settings))
        db.session.commit()


with app.app_context():
    db.create_all()
    seed_if_empty()


# ============================================================================
# 14. ENTRYPOINT
# ============================================================================
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') != 'production'
    if debug:
        log.warning('Running in DEBUG mode — do not use this in production. '
                     'Use: gunicorn -w 4 --threads 4 -b 0.0.0.0:%s app:app', port)
    app.run(host='0.0.0.0', port=port, debug=debug)
