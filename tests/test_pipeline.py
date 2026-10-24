"""Synthetic captured frames through the real durable queue and loopback HTTP."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid

from tatocatch.capture import EventAdapter, consume_process
from tatocatch.delivery import IngestClient, Outbox


class PipelineTests(unittest.TestCase):
    def test_capture_to_http_preserves_unicode_chat_scope_and_native_idempotence(self):
        captured = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers['Content-Length']))
                payload = json.loads(body)
                captured.append((self.path, self.headers.get('Authorization'), payload))
                response = json.dumps({'ok': True, 'data': {'receipt_id': len(captured), 'source_id': 1,
                    'message_id': payload['message_id'], 'conversation_id': payload['conversation_id'],
                    'status': 'queued', 'duplicate': False}}).encode()
                self.send_response(202)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(response)))
                self.end_headers()
                self.wfile.write(response)
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        endpoint = 'http://127.0.0.1:' + str(server.server_port) + '/api/ingest/v1/messages'
        token = 'tgfi_' + 'synthetic' * 5
        text = ' 相同正文🙂\n保留空格 '
        events = [dict(event_key=str(index), text=text, conversation_id=peer, message_id=message,
                       sender='123') for index, (peer, message) in enumerate(
                           [('chat:1', '7'), ('chat:1', '8'), ('chat:2', '7'), ('chat:1', '7')])]
        helper_source = ('import json,sys\n' +
            'events=json.loads(sys.argv[1])\nprint("TATO_LISTENER_READY",flush=True)\n' +
            'for event in events:\n print("TATO_TEXT_EVENT:"+json.dumps(event),flush=True)\n' +
            'sys.stdin.read()\n')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'outbox.sqlite3'
            outbox = Outbox(path)
            try:
                adapter = EventAdapter(uuid.uuid4().hex, 'fallback')
                stop = threading.Event()
                observations = []
                def receive(event):
                    observations.append(event)
                    outbox.enqueue(adapter.convert(event))
                    if len(observations) == len(events):
                        stop.set()
                helper = subprocess.Popen([sys.executable, '-u', '-c', helper_source, json.dumps(events)],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, encoding='utf-8')
                consume_process(helper, stop, receive, ready_timeout=3, heartbeat_timeout=3)
                self.assertEqual(outbox.stats()['pending'], 3)
                client = IngestClient(endpoint, token)
                for _ in range(3):
                    self.assertEqual(outbox.deliver_one(client), 'delivered')
                self.assertEqual(outbox.deliver_one(client), 'idle')
                self.assertEqual(len(captured), 3)
                self.assertEqual({item[2]['text'] for item in captured}, {text})
                self.assertEqual(len({item[2]['conversation_id'] for item in captured}), 2)
                self.assertTrue(all(item[0] == '/api/ingest/v1/messages' for item in captured))
                self.assertTrue(all(item[1] == 'Bearer ' + token for item in captured))
                self.assertTrue(all('timestamp' not in item[2] and 'event_key' not in item[2] for item in captured))
                payload = adapter.convert(events[0])
            finally:
                outbox.close()
            reopened = Outbox(path)
            try:
                self.assertFalse(reopened.enqueue(payload))
                self.assertEqual(reopened.stats()['delivered'], 3)
            finally:
                reopened.close()


if __name__ == '__main__':
    unittest.main()
