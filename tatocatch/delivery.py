"""Validated text ingestion and a durable local delivery outbox.

An accepted receipt means the server queued the message; publication is a
separate server operation. No request bodies or credentials are logged here.
"""
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.client import HTTPException
import ipaddress
import json
import math
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class DeliveryError(ValueError):
    """A safe delivery failure; never includes server text or credentials."""

    def __init__(self, message, *, retryable=False, status=None, retry_after=None):
        super().__init__(message)
        self.retryable = retryable
        self.status = status
        self.retry_after = retry_after


def _endpoint(value):
    if (not isinstance(value, str) or not value
            or any(ord(char) <= 32 or ord(char) == 127 for char in value)
            or "?" in value or "#" in value):
        raise ValueError("Invalid ingest endpoint")
    try:
        parts = urlsplit(value)
        host = parts.hostname
        port = parts.port
        if (not host or parts.username is not None or parts.password is not None
                or parts.path != "/api/ingest/v1/messages" or "\\" in value):
            raise ValueError
        loopback = host.lower() == "localhost"
        if not loopback:
            try:
                loopback = ipaddress.ip_address(host).is_loopback
            except ValueError:
                pass
        if parts.scheme != "https" and not (parts.scheme == "http" and loopback):
            raise ValueError
        if port is not None and port < 1:
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError("Invalid ingest endpoint") from None
    return value


def _payload(value):
    allowed = {"message_id", "text", "conversation_id", "sender", "conversation_name", "timestamp"}
    if not isinstance(value, dict) or set(value) - allowed:
        raise DeliveryError("Invalid message fields")
    result = dict(value)
    result.setdefault("conversation_id", "default")
    for name, limit in (("message_id", 128), ("text", 65536), ("conversation_id", 128)):
        item = result.get(name)
        if not isinstance(item, str) or not item.strip() or len(item) > limit:
            raise DeliveryError("Invalid message field: " + name)
    for name in ("sender", "conversation_name"):
        item = result.get(name)
        if item is not None and (not isinstance(item, str) or len(item) > 256):
            raise DeliveryError("Invalid message field: " + name)
    timestamp = result.get("timestamp")
    if timestamp is not None:
        try:
            if not isinstance(timestamp, str) or "T" not in timestamp:
                raise ValueError
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError
        except (ValueError, TypeError, OverflowError):
            raise DeliveryError("Invalid message field: timestamp") from None
    try:
        json.dumps(result, ensure_ascii=False).encode("utf-8")
    except (UnicodeError, TypeError, ValueError):
        raise DeliveryError("Invalid message encoding") from None
    return result


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


def _retry_after(value):
    if value is None:
        return None
    try:
        seconds = float(value)
        if not math.isfinite(seconds):
            return None
    except (TypeError, ValueError):
        try:
            instant = parsedate_to_datetime(value)
            if instant.tzinfo is None:
                return None
            seconds = (instant - datetime.now(timezone.utc)).total_seconds()
        except (TypeError, ValueError, OverflowError):
            return None
    return min(3600.0, max(0.0, seconds))


def _http_failure(status, retry_header=None):
    retryable = status == 429 or status >= 500 or 200 <= status < 300
    return DeliveryError("Ingest HTTP failure (%d)" % status, retryable=retryable,
                         status=status, retry_after=_retry_after(retry_header) if retryable else None)


def _receipt(raw, payload, status):
    try:
        response = json.loads(raw)
        if not isinstance(response, dict) or response.get("ok") is not True:
            raise ValueError
        data = response["data"]
        if (not isinstance(data, dict) or type(data.get("receipt_id")) is not int
                or data["receipt_id"] <= 0 or type(data.get("source_id")) is not int
                or data["source_id"] <= 0 or data.get("message_id") != payload["message_id"]
                or data.get("conversation_id") != payload["conversation_id"]
                or data.get("status") != "queued" or type(data.get("duplicate")) is not bool):
            raise ValueError
        return {name: data[name] for name in ("receipt_id", "source_id", "message_id", "conversation_id", "status", "duplicate")}
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise DeliveryError("Invalid ingest receipt", retryable=True, status=status) from None


class IngestClient:
    """POST one validated message without following redirects."""

    def __init__(self, endpoint, token, timeout=30):
        self.endpoint = _endpoint(endpoint)
        if not isinstance(token, str) or re.fullmatch(r"tgfi_[A-Za-z0-9_-]+", token) is None:
            raise ValueError("Invalid ingest token")
        if (not isinstance(timeout, (int, float)) or isinstance(timeout, bool)
                or not math.isfinite(timeout) or timeout <= 0):
            raise ValueError("Invalid ingest timeout")
        self.timeout = timeout
        self._token = token
        self._opener = build_opener(_NoRedirect())

    def submit(self, payload):
        message = _payload(payload)
        body = json.dumps(message, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        request = Request(self.endpoint, data=body, headers={"Authorization": "Bearer " + self._token,
                          "Content-Type": "application/json", "Accept": "application/json"}, method="POST")
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                status = response.status
                if status not in (200, 202):
                    raise _http_failure(status, response.headers.get("Retry-After"))
                raw = response.read(65537)
                if len(raw) > 65536:
                    raise DeliveryError("Invalid ingest receipt", retryable=True, status=status)
                return _receipt(raw, message, status)
        except HTTPError as error:
            status = error.code
            retry_header = error.headers.get("Retry-After") if error.headers is not None else None
            error.close()
            raise _http_failure(status, retry_header) from None
        except (URLError, OSError, HTTPException):
            raise DeliveryError("Ingest connection failed", retryable=True) from None

class Outbox:
    """Persist frozen payloads and deliver one due record at a time.

    A queue is bound to its first endpoint. Reopen it after fixing a 401 token
    failure. Delivered rows keep only identity, hash, and the queued receipt.
    """

    def __init__(self, path, *, max_pending=100000):
        import sqlite3
        import threading
        from pathlib import Path

        if type(max_pending) is not int or max_pending < 1:
            raise ValueError("Invalid outbox capacity")
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._max_pending = max_pending
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._active_requests = 0
        self._auth_blocked = False
        self._closing = False
        self._closed = False
        self._connection = sqlite3.connect(path, check_same_thread=False, timeout=30)
        self._connection.row_factory = sqlite3.Row
        try:
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute("PRAGMA secure_delete=ON")
            with self._connection:
                self._connection.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                self._connection.execute("""CREATE TABLE IF NOT EXISTS messages (
                    conversation_id TEXT NOT NULL, message_id TEXT NOT NULL,
                    payload TEXT, payload_hash TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('pending','inflight','delivered','failed')),
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt REAL NOT NULL DEFAULT 0,
                    error_category TEXT, receipt TEXT,
                    PRIMARY KEY (conversation_id, message_id))""")
                self._connection.execute("CREATE INDEX IF NOT EXISTS due_messages ON messages(state, next_attempt)")
                self._connection.execute("UPDATE messages SET state = 'pending', next_attempt = 0 WHERE state = 'inflight'")
        except BaseException:
            self._connection.close()
            raise

    def _ensure_open(self):
        if self._closed or self._closing:
            raise ValueError("Outbox is closed")

    def _bind_locked(self, endpoint):
        existing = self._connection.execute("SELECT value FROM metadata WHERE key = 'endpoint'").fetchone()
        if existing is not None and existing[0] != endpoint:
            raise ValueError("Outbox is bound to a different endpoint; use a separate queue")
        self._connection.execute("INSERT OR IGNORE INTO metadata(key, value) VALUES ('endpoint', ?)", (endpoint,))

    def bind_endpoint(self, endpoint):
        """Reject accidental reuse of a queue with a different ingest server."""
        endpoint = _endpoint(endpoint)
        with self._lock:
            self._ensure_open()
            with self._connection:
                self._bind_locked(endpoint)

    def enqueue(self, payload):
        import hashlib

        message = _payload(payload)
        frozen = json.dumps(message, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        digest = hashlib.sha256(frozen.encode("utf-8")).hexdigest()
        identity = (message["conversation_id"], message["message_id"])
        with self._lock:
            self._ensure_open()
            with self._connection:
                existing = self._connection.execute(
                    "SELECT payload_hash FROM messages WHERE conversation_id = ? AND message_id = ?", identity).fetchone()
                if existing is not None:
                    if existing[0] != digest:
                        raise ValueError("Message identity already has a different payload")
                    return False
                count = self._connection.execute("SELECT COUNT(*) FROM messages WHERE state != 'delivered'").fetchone()[0]
                if count >= self._max_pending:
                    raise ValueError("Outbox capacity reached; stop capture and resolve queued messages")
                self._connection.execute("""INSERT INTO messages
                    (conversation_id, message_id, payload, payload_hash, state)
                    VALUES (?, ?, ?, ?, 'pending')""", (*identity, frozen, digest))
                return True

    def deliver_one(self, client, now=None):
        import time

        if now is not None and (not isinstance(now, (int, float)) or isinstance(now, bool) or not math.isfinite(now)):
            raise ValueError("Invalid delivery time")
        current = time.time() if now is None else now
        endpoint = _endpoint(client.endpoint)
        with self._condition:
            self._ensure_open()
            with self._connection:
                self._bind_locked(endpoint)
                if self._auth_blocked:
                    return "auth_blocked"
                if self._active_requests:
                    return "idle"
                row = self._connection.execute("""SELECT rowid, payload, attempts FROM messages
                    WHERE state = 'pending' AND next_attempt <= ? ORDER BY rowid LIMIT 1""", (current,)).fetchone()
                if row is None:
                    return "idle"
                self._connection.execute("UPDATE messages SET state = 'inflight', attempts = attempts + 1 WHERE rowid = ?", (row["rowid"],))
            self._active_requests += 1
        error = None
        try:
            receipt = client.submit(json.loads(row["payload"]))
        except DeliveryError as caught:
            error = caught
        except BaseException:
            with self._condition:
                try:
                    with self._connection:
                        self._connection.execute("UPDATE messages SET state = 'pending' WHERE rowid = ?", (row["rowid"],))
                finally:
                    self._active_requests -= 1
                    self._condition.notify_all()
            raise
        with self._condition:
            try:
                with self._connection:
                    if error is None:
                        self._connection.execute("""UPDATE messages SET state = 'delivered', payload = NULL,
                            receipt = ?, next_attempt = 0, error_category = NULL WHERE rowid = ?""",
                            (json.dumps(receipt, sort_keys=True, separators=(",", ":")), row["rowid"]))
                        result = "delivered"
                    else:
                        category = ("auth" if error.status == 401 else
                                    "receipt" if error.status is not None and 200 <= error.status < 300 else
                                    "http_%d" % error.status if error.status is not None else
                                    "network" if error.retryable else "invalid_request")
                        if error.status == 401:
                            self._auth_blocked = True
                            state, next_attempt, result = "pending", 0, "auth_blocked"
                        elif error.retryable:
                            delay = min(300, 2 ** min(row["attempts"] + 1, 9))
                            if error.retry_after is not None:
                                delay = max(delay, min(3600, max(0, error.retry_after)))
                            next_attempt = (time.time() if now is None else now) + delay
                            state, result = "pending", "retry"
                        else:
                            state, next_attempt, result = "failed", 0, "failed"
                        self._connection.execute("""UPDATE messages SET state = ?, next_attempt = ?,
                            error_category = ? WHERE rowid = ?""", (state, next_attempt, category, row["rowid"]))
                return result
            finally:
                self._active_requests -= 1
                self._condition.notify_all()

    def stats(self):
        with self._lock:
            self._ensure_open()
            result = {"pending": 0, "delivered": 0, "failed": 0}
            for state, count in self._connection.execute("SELECT state, COUNT(*) FROM messages GROUP BY state"):
                result["pending" if state == "inflight" else state] += count
            return result

    def retry_failed(self):
        with self._lock:
            self._ensure_open()
            with self._connection:
                cursor = self._connection.execute("""UPDATE messages SET state = 'pending',
                    next_attempt = 0, error_category = NULL WHERE state = 'failed'""")
                return cursor.rowcount

    def close(self):
        with self._condition:
            if self._closed:
                return
            self._closing = True
            while self._active_requests:
                self._condition.wait()
            self._connection.close()
            self._closed = True
