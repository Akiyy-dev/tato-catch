"""Remote ingest checks use synthetic payloads and a loopback HTTP server."""
import importlib
from contextlib import closing
import json
from pathlib import Path
import queue
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import unittest

try:
    delivery = importlib.import_module("tatocatch.delivery")
except ModuleNotFoundError:
    delivery = None

TOKEN = "tgfi_" + "synthetic-test-token"
PAYLOAD = {"message_id": "message-1", "text": "  hello\n世界  "}


def accepted(payload=None, duplicate=False):
    payload = PAYLOAD if payload is None else payload
    return {"ok": True, "data": {"receipt_id": 7, "source_id": 3,
            "message_id": payload["message_id"],
            "conversation_id": payload.get("conversation_id", "default"),
            "status": "queued", "duplicate": duplicate}}


class LocalIngest:
    def __init__(self):
        self.responses = queue.Queue()
        self.requests = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                owner.requests.append((self.path, dict(self.headers), body))
                status, response, headers = owner.responses.get(timeout=2)
                if callable(response):
                    response = response()
                if not isinstance(response, bytes):
                    response = json.dumps(response).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                for name, value in headers.items():
                    self.send_header(name, value)
                self.end_headers()
                try:
                    self.wfile.write(response)
                except ConnectionError:
                    pass

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=lambda: self.server.serve_forever(poll_interval=0.01), daemon=True)
        self.thread.start()
        self.endpoint = "http://127.0.0.1:%d/api/ingest/v1/messages" % self.server.server_port

    def reply(self, status=202, body=None, **headers):
        self.responses.put((status, accepted() if body is None else body, headers))

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class IngestClientTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(delivery, "The remote delivery implementation is missing")
        self.server = LocalIngest()
        self.addCleanup(self.server.close)
        self.client = delivery.IngestClient(self.server.endpoint, TOKEN)

    def test_posts_text_without_trimming_or_adding_timestamp(self):
        self.server.reply()
        self.assertEqual(self.client.submit(dict(PAYLOAD)), accepted()["data"])
        path, headers, body = self.server.requests[0]
        self.assertEqual(path, "/api/ingest/v1/messages")
        self.assertEqual(headers["Authorization"], "Bearer " + TOKEN)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(json.loads(body), {**PAYLOAD, "conversation_id": "default"})
        self.assertEqual(PAYLOAD, {"message_id": "message-1", "text": "  hello\n世界  "})
        self.assertEqual(self.client.timeout, 30)

    def test_200_and_202_duplicate_receipts_mean_queued(self):
        for status in (200, 202):
            with self.subTest(status=status):
                self.server.reply(status, accepted(duplicate=True))
                receipt = self.client.submit(PAYLOAD)
                self.assertIs(receipt["duplicate"], True)
                self.assertEqual(receipt["status"], "queued")

    def test_request_schema_rejects_unrecognized_fields_and_invalid_values(self):
        invalid = [None, [], {}, {"message_id": "id"}, {"text": "hello"},
                   {**PAYLOAD, "message_id": " "}, {**PAYLOAD, "message_id": "x" * 129},
                   {**PAYLOAD, "message_id": 12}, {**PAYLOAD, "text": "\n "},
                   {**PAYLOAD, "text": "x" * 65537}, {**PAYLOAD, "text": None},
                   {**PAYLOAD, "conversation_id": None}, {**PAYLOAD, "conversation_id": " "},
                   {**PAYLOAD, "conversation_id": "x" * 129},
                   {**PAYLOAD, "sender": "x" * 257}, {**PAYLOAD, "sender": 1},
                   {**PAYLOAD, "conversation_name": "x" * 257},
                   {**PAYLOAD, "timestamp": "2026-01-02T03:04:05"},
                   {**PAYLOAD, "timestamp": "2026-01-02"}, {**PAYLOAD, "timestamp": 1},
                   {**PAYLOAD, "media": {}}, {**PAYLOAD, "target": "somewhere"}]
        for payload in invalid:
            with self.subTest(payload_type=type(payload).__name__), self.assertRaises(delivery.DeliveryError) as raised:
                self.client.submit(payload)
            self.assertFalse(raised.exception.retryable)
            self.assertIsNone(raised.exception.status)
        self.assertEqual(self.server.requests, [])

    def test_optional_fields_and_character_boundaries_are_preserved(self):
        payload = {"message_id": "x" * 128, "text": "界" * 65536,
                   "conversation_id": "c" * 128, "sender": None,
                   "conversation_name": "n" * 256, "timestamp": "2026-01-02T03:04:05+08:00"}
        self.server.reply(202, accepted(payload))
        self.client.submit(payload)
        self.assertEqual(json.loads(self.server.requests[0][2]), payload)
        self.server.reply(202, accepted())
        self.client.submit({**PAYLOAD, "sender": "", "conversation_name": None, "timestamp": None})
        self.assertIsNone(json.loads(self.server.requests[1][2])["timestamp"])

    def test_endpoint_and_credentials_are_rejected_before_network(self):
        for endpoint in ("http://example.invalid/api/ingest/v1/messages",
                         "https://name:password@example.invalid/api/ingest/v1/messages",
                         "https://example.invalid/api/ingest/v1/messages?token=private",
                         "https://example.invalid/api/ingest/v1/messages#fragment",
                         "ftp://example.invalid/api/ingest/v1/messages",
                         "https://example.invalid/another-path",
                         "https://example.invalid/api/ingest/v1/messages\n",
                         "http://127.0.0.1.example.invalid/api/ingest/v1/messages"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                delivery.IngestClient(endpoint, TOKEN)
        for token in ("bad", "tgfi_", "tgfi_bad\r\nsecret", "tgfi_bad token", "tgfi_测试"):
            with self.subTest(token_type="synthetic"), self.assertRaises(ValueError) as raised:
                delivery.IngestClient(self.server.endpoint, token)
            self.assertNotIn(token, str(raised.exception))
        for timeout in (0, -1, float("inf"), float("nan")):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                delivery.IngestClient(self.server.endpoint, TOKEN, timeout=timeout)
        self.assertEqual(self.server.requests, [])

    def test_http_errors_are_classified_without_response_content(self):
        for status, retryable in ((401, False), (409, False), (422, False), (429, True), (500, True), (503, True)):
            with self.subTest(status=status):
                self.server.reply(status, b"private response text", **{"Retry-After": "17"})
                with self.assertRaises(delivery.DeliveryError) as raised:
                    self.client.submit(PAYLOAD)
                self.assertEqual(raised.exception.status, status)
                self.assertEqual(raised.exception.retryable, retryable)
                self.assertNotIn("private", str(raised.exception))
                self.assertNotIn(TOKEN, str(raised.exception))
                self.assertNotIn(PAYLOAD["text"], str(raised.exception))
                self.assertEqual(raised.exception.retry_after, 17 if retryable else None)

    def test_redirect_is_not_followed_with_authorization(self):
        other = LocalIngest()
        self.addCleanup(other.close)
        other.reply()
        self.server.reply(307, {}, Location=other.endpoint)
        with self.assertRaises(delivery.DeliveryError) as raised:
            self.client.submit(PAYLOAD)
        self.assertFalse(raised.exception.retryable)
        self.assertEqual(other.requests, [])
        self.assertEqual(len(self.server.requests), 1)

    def test_malformed_successes_are_retryable(self):
        cases = [b"not JSON", b"[" * (sys.getrecursionlimit() + 100) + b"]" * (sys.getrecursionlimit() + 100), [], {"ok": False, "data": accepted()["data"]},
                 {"ok": True}, {"ok": True, "data": {}},
                 {"ok": True, "data": {**accepted()["data"], "status": "published"}},
                 {"ok": True, "data": {**accepted()["data"], "message_id": "other"}},
                 {"ok": True, "data": {**accepted()["data"], "conversation_id": "other"}},
                 {"ok": True, "data": {**accepted()["data"], "receipt_id": True}},
                 {"ok": True, "data": {**accepted()["data"], "source_id": 0}},
                 {"ok": True, "data": {**accepted()["data"], "duplicate": "false"}}]
        for body in cases:
            with self.subTest(body_type=type(body).__name__):
                self.server.reply(202, body)
                with self.assertRaises(delivery.DeliveryError) as raised:
                    self.client.submit(PAYLOAD)
                self.assertTrue(raised.exception.retryable)
                self.assertEqual(raised.exception.status, 202)

    def test_connection_failure_is_retryable_and_safe(self):
        endpoint = self.server.endpoint
        self.server.close()
        self.client = delivery.IngestClient(endpoint, TOKEN, timeout=0.2)
        with self.assertRaises(delivery.DeliveryError) as raised:
            self.client.submit(PAYLOAD)
        self.assertTrue(raised.exception.retryable)
        self.assertIsNone(raised.exception.status)
        self.assertNotIn(TOKEN, str(raised.exception))

    def test_truncated_chunked_response_is_a_retryable_transport_failure(self):
        self.server.reply(202, b"5\r\nabc", **{"Transfer-Encoding": "chunked"})
        with self.assertRaises(delivery.DeliveryError) as raised:
            self.client.submit(PAYLOAD)
        self.assertTrue(raised.exception.retryable)
        self.assertNotIn(TOKEN, str(raised.exception))

    def test_timeout_is_retryable(self):
        release = threading.Event()
        self.addCleanup(release.set)
        self.server.reply(202, lambda: (release.wait(timeout=1), accepted())[1])
        client = delivery.IngestClient(self.server.endpoint, TOKEN, timeout=0.02)
        with self.assertRaises(delivery.DeliveryError) as raised:
            client.submit(PAYLOAD)
        self.assertTrue(raised.exception.retryable)
        self.assertIsNone(raised.exception.status)
        release.set()

    def test_retry_after_http_date_and_invalid_value(self):
        from datetime import datetime, timedelta, timezone
        from email.utils import format_datetime
        value = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=30), usegmt=True)
        self.server.reply(429, {}, **{"Retry-After": value})
        with self.assertRaises(delivery.DeliveryError) as raised:
            self.client.submit(PAYLOAD)
        self.assertGreater(raised.exception.retry_after, 27)
        self.assertLessEqual(raised.exception.retry_after, 30)
        self.server.reply(503, {}, **{"Retry-After": "invalid"})
        with self.assertRaises(delivery.DeliveryError) as raised:
            self.client.submit(PAYLOAD)
        self.assertIsNone(raised.exception.retry_after)


class OutboxTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(delivery, "The remote delivery implementation is missing")
        self.assertTrue(hasattr(delivery, "Outbox"), "The persistent outbox implementation is missing")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "outbox.sqlite3"
        self.outbox = delivery.Outbox(self.path)
        self.addCleanup(lambda: self.outbox.close())
        self.server = LocalIngest()
        self.addCleanup(self.server.close)
        self.client = delivery.IngestClient(self.server.endpoint, TOKEN)

    def record(self):
        import sqlite3
        with closing(sqlite3.connect(self.path)) as connection:
            connection.row_factory = sqlite3.Row
            return dict(connection.execute("SELECT * FROM messages ORDER BY rowid LIMIT 1").fetchone())

    def reopen(self):
        self.outbox.close()
        self.outbox = delivery.Outbox(self.path)

    def test_payload_is_frozen_and_identity_dedup_survives_restart(self):
        payload = dict(PAYLOAD)
        self.assertTrue(self.outbox.enqueue(payload))
        payload["text"] = "mutated after enqueue"
        self.reopen()
        self.assertFalse(self.outbox.enqueue(PAYLOAD))
        with self.assertRaises(ValueError):
            self.outbox.enqueue(payload)
        self.assertTrue(self.outbox.enqueue({**PAYLOAD, "message_id": "message-2"}))
        self.assertTrue(self.outbox.enqueue({**PAYLOAD, "conversation_id": "another-chat"}))
        self.assertEqual(self.outbox.stats(), {"pending": 3, "delivered": 0, "failed": 0})
        self.server.reply()
        self.assertEqual(self.outbox.deliver_one(self.client, now=100), "delivered")
        self.assertEqual(json.loads(self.server.requests[0][2])["text"], PAYLOAD["text"])

    def test_delivered_tombstone_discards_payload_but_preserves_receipt_and_dedup(self):
        self.outbox.enqueue(PAYLOAD)
        self.server.reply(202, accepted(duplicate=True))
        self.assertEqual(self.outbox.deliver_one(self.client, now=100), "delivered")
        row = self.record()
        self.assertIsNone(row["payload"])
        self.assertEqual(json.loads(row["receipt"]), accepted(duplicate=True)["data"])
        self.assertEqual(row["attempts"], 1)
        self.reopen()
        self.assertFalse(self.outbox.enqueue(PAYLOAD))
        with self.assertRaises(ValueError):
            self.outbox.enqueue({**PAYLOAD, "text": "different"})
        self.assertEqual(self.outbox.stats(), {"pending": 0, "delivered": 1, "failed": 0})
        self.assertEqual(self.outbox.deliver_one(self.client, now=200), "idle")
        self.assertNotIn(TOKEN.encode(), self.path.read_bytes())

    def test_retry_backoff_is_persisted_and_timestamp_stays_omitted(self):
        self.outbox.enqueue(PAYLOAD)
        self.server.reply(503, b"private failure")
        self.assertEqual(self.outbox.deliver_one(self.client, now=100), "retry")
        self.assertEqual(self.record()["next_attempt"], 102)
        self.assertEqual(self.record()["attempts"], 1)
        self.reopen()
        self.assertEqual(self.outbox.deliver_one(self.client, now=101), "idle")
        self.server.reply()
        self.assertEqual(self.outbox.deliver_one(self.client, now=102), "delivered")
        self.assertEqual(self.server.requests[0][2], self.server.requests[1][2])
        self.assertNotIn("timestamp", json.loads(self.server.requests[1][2]))

    def test_exponential_backoff_caps_at_five_minutes(self):
        self.outbox.enqueue(PAYLOAD)
        now = 100
        for delay in (2, 4, 8, 16, 32, 64, 128, 256, 300, 300):
            self.server.reply(500, {})
            self.assertEqual(self.outbox.deliver_one(self.client, now=now), "retry")
            self.assertEqual(self.record()["next_attempt"], now + delay)
            now += delay

    def test_retry_after_is_honored_and_capped_at_one_hour(self):
        self.outbox.enqueue(PAYLOAD)
        self.server.reply(429, {}, **{"Retry-After": "9000"})
        self.assertEqual(self.outbox.deliver_one(self.client, now=100), "retry")
        self.assertEqual(self.outbox.deliver_one(self.client, now=3699), "idle")
        self.assertEqual(self.record()["next_attempt"], 3700)
        self.server.reply(503, {}, **{"Retry-After": "15"})
        self.assertEqual(self.outbox.deliver_one(self.client, now=3700), "retry")
        self.assertEqual(self.record()["next_attempt"], 3715)

    def test_auth_failure_pauses_instance_without_losing_queue(self):
        self.outbox.enqueue(PAYLOAD)
        self.server.reply(401, {"private": TOKEN})
        self.assertEqual(self.outbox.deliver_one(self.client, now=100), "auth_blocked")
        self.assertEqual(self.outbox.stats(), {"pending": 1, "delivered": 0, "failed": 0})
        self.assertEqual(self.outbox.deliver_one(self.client, now=10000), "auth_blocked")
        self.assertEqual(len(self.server.requests), 1)
        self.assertEqual(self.record()["error_category"], "auth")
        self.assertNotIn(TOKEN.encode(), self.path.read_bytes())
        self.reopen()
        self.server.reply()
        self.assertEqual(self.outbox.deliver_one(self.client, now=10000), "delivered")

    def test_conflicts_and_validation_failures_require_explicit_retry(self):
        for status in (409, 422):
            with self.subTest(status=status):
                message = {**PAYLOAD, "message_id": "message-" + str(status)}
                self.outbox.enqueue(message)
                self.server.reply(status, {"private": TOKEN})
                self.assertEqual(self.outbox.deliver_one(self.client, now=100), "failed")
        self.assertEqual(self.outbox.stats(), {"pending": 0, "delivered": 0, "failed": 2})
        self.assertEqual(self.outbox.deliver_one(self.client, now=10000), "idle")
        self.reopen()
        self.assertEqual(self.outbox.deliver_one(self.client, now=20000), "idle")
        self.assertEqual(self.outbox.retry_failed(), 2)
        self.assertEqual(self.outbox.stats(), {"pending": 2, "delivered": 0, "failed": 0})
        message = {**PAYLOAD, "message_id": "message-409"}
        self.server.reply(202, accepted(message))
        self.assertEqual(self.outbox.deliver_one(self.client), "delivered")

    def test_server_response_details_are_not_persisted_in_errors(self):
        self.outbox.enqueue(PAYLOAD)
        self.server.reply(503, {"body": "secret response data", "token": TOKEN})
        self.assertEqual(self.outbox.deliver_one(self.client, now=100), "retry")
        row = self.record()
        self.assertEqual(row["error_category"], "http_503")
        self.assertNotIn("secret response data", str(row))
        self.assertNotIn(TOKEN, str(row))

    def test_endpoint_binding_persists_even_for_an_empty_queue(self):
        self.assertEqual(self.outbox.deliver_one(self.client, now=100), "idle")
        self.outbox.enqueue(PAYLOAD)
        self.reopen()
        other = delivery.IngestClient("https://example.invalid/api/ingest/v1/messages", TOKEN)
        with self.assertRaisesRegex(ValueError, "endpoint"):
            self.outbox.deliver_one(other, now=100)
        self.assertEqual(self.outbox.stats()["pending"], 1)
        self.assertEqual(self.server.requests, [])

    def test_inflight_work_is_recovered_after_a_process_interruption(self):
        self.outbox.enqueue(PAYLOAD)
        self.outbox.close()
        import sqlite3
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("UPDATE messages SET state = 'inflight', attempts = 1")
            connection.commit()
        self.outbox = delivery.Outbox(self.path)
        self.server.reply()
        self.assertEqual(self.outbox.deliver_one(self.client, now=100), "delivered")
        self.assertEqual(self.record()["attempts"], 2)

    def test_producer_enqueue_is_not_blocked_by_an_http_request(self):
        self.outbox.enqueue(PAYLOAD)
        entered = threading.Event()
        release = threading.Event()
        results = []
        failures = []

        def slow_response():
            entered.set()
            release.wait(timeout=3)
            return accepted()

        def send():
            try:
                results.append(self.outbox.deliver_one(self.client, now=100))
            except Exception as error:
                failures.append(error)

        self.server.reply(202, slow_response)
        worker = threading.Thread(target=send)
        worker.start()
        self.assertTrue(entered.wait(timeout=2))
        try:
            producer = threading.Thread(target=lambda: results.append(self.outbox.enqueue({**PAYLOAD, "message_id": "message-2"})))
            producer.start()
            producer.join(timeout=0.5)
            self.assertFalse(producer.is_alive(), "HTTP must not hold the producer lock")
            self.assertEqual(self.outbox.stats()["pending"], 2)
            self.assertEqual(self.outbox.deliver_one(self.client, now=100), "idle")
        finally:
            release.set()
            worker.join(timeout=3)
        self.assertEqual(failures, [])
        self.assertIn("delivered", results)
        self.assertIn(True, results)

    def test_pending_capacity_stops_capture_without_discarding_existing_messages(self):
        self.outbox.close()
        self.outbox = delivery.Outbox(self.path, max_pending=1)
        self.assertTrue(self.outbox.enqueue(PAYLOAD))
        self.assertFalse(self.outbox.enqueue(PAYLOAD))
        with self.assertRaisesRegex(ValueError, "capacity"):
            self.outbox.enqueue({**PAYLOAD, "message_id": "message-2"})
        self.assertEqual(self.outbox.stats()["pending"], 1)
        self.server.reply()
        self.assertEqual(self.outbox.deliver_one(self.client, now=100), "delivered")
        self.assertTrue(self.outbox.enqueue({**PAYLOAD, "message_id": "message-2"}))


    def test_delayed_retry_does_not_block_another_due_message(self):
        self.outbox.enqueue(PAYLOAD)
        self.server.reply(503, {})
        self.assertEqual(self.outbox.deliver_one(self.client, now=100), "retry")
        other = {**PAYLOAD, "message_id": "message-2"}
        self.outbox.enqueue(other)
        self.server.reply(202, accepted(other))
        self.assertEqual(self.outbox.deliver_one(self.client, now=101), "delivered")
        self.assertEqual(self.outbox.stats(), {"pending": 1, "delivered": 1, "failed": 0})

    def test_ambiguous_success_is_replayed_identically_and_duplicate_is_accepted(self):
        self.outbox.enqueue(PAYLOAD)
        self.server.reply(202, {"ok": True})
        self.assertEqual(self.outbox.deliver_one(self.client, now=100), "retry")
        self.assertEqual(self.record()["error_category"], "receipt")
        self.reopen()
        self.server.reply(202, accepted(duplicate=True))
        self.assertEqual(self.outbox.deliver_one(self.client, now=102), "delivered")
        self.assertEqual(self.server.requests[0][2], self.server.requests[1][2])
        self.assertTrue(json.loads(self.record()["receipt"])["duplicate"])

    def test_invalid_payload_never_enters_the_durable_queue(self):
        with self.assertRaises(ValueError):
            self.outbox.enqueue({**PAYLOAD, "media": "private-content"})
        self.assertEqual(self.outbox.stats(), {"pending": 0, "delivered": 0, "failed": 0})


    def test_receipt_decoder_depth_failure_keeps_message_retryable(self):
        from unittest.mock import patch
        self.outbox.enqueue(PAYLOAD)
        nested = b"[" * (sys.getrecursionlimit() + 100) + b"]" * (sys.getrecursionlimit() + 100)
        self.server.reply(202, nested)
        real_loads = json.loads

        def limited_decoder(raw, *args, **kwargs):
            # Python versions differ in whether their C JSON decoder limits depth.
            # Inject the documented decoder failure only for the server response;
            # queue decoding and the complete HTTP request still use real code.
            if isinstance(raw, bytes) and raw == nested:
                raise RecursionError("synthetic private decoder detail")
            return real_loads(raw, *args, **kwargs)

        with patch.object(delivery.json, "loads", side_effect=limited_decoder):
            self.assertEqual(self.outbox.deliver_one(self.client, now=100), "retry")
        row = self.record()
        self.assertEqual(row["error_category"], "receipt")
        self.assertEqual(row["next_attempt"], 102)
        self.assertNotIn("private decoder detail", str(row))
        self.assertEqual(self.outbox.stats(), {"pending": 1, "delivered": 0, "failed": 0})
        self.server.reply(202, accepted(duplicate=True))
        self.assertEqual(self.outbox.deliver_one(self.client, now=102), "delivered")
        self.assertEqual(self.server.requests[0][2], self.server.requests[1][2])


if __name__ == "__main__":
    unittest.main()
