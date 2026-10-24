"""Pure framing/configuration tests and synthetic child-process lifecycle tests."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid

from tatocatch.config import ConfigurationError, StateLock, load_settings
from tatocatch.capture import CaptureError, EventAdapter, consume_process, parse_frame
from tatocatch.service import run_sender, state_namespace


class ConfigurationTests(unittest.TestCase):
    def test_env_overrides_local_config_and_repr_hides_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            path.write_text(json.dumps({'ingest_url': 'https://example.invalid',
                'ingest_token': 'tgfi_' + 'a' * 32, 'target_exe': 'Tatotalk.exe',
                'conversation_id': 'test-stream', 'state_dir': directory}))
            token = 'tgfi_' + 'b' * 32
            settings = load_settings({'TATO_INGEST_TOKEN': token}, path)
            self.assertEqual(settings.token, token)
            self.assertEqual(settings.endpoint, 'https://example.invalid/api/ingest/v1/messages')
            self.assertNotIn(token, repr(settings))
            self.assertEqual(settings.conversation_id, 'test-stream')

    def test_invalid_or_unknown_config_fails_without_echoing_private_values(self):
        private = 'do-not-copy-this-value'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            path.write_text(json.dumps({'unexpected': private}))
            with self.assertRaises(ConfigurationError) as caught:
                load_settings({}, path)
            self.assertNotIn(private, str(caught.exception))
        for env in ({}, {'TATO_INGEST_URL': 'https://example.invalid', 'TATO_INGEST_TOKEN': 'tgf_wrong'}):
            with self.subTest(env=env), self.assertRaises(ConfigurationError):
                load_settings(env)

    def test_queue_commands_do_not_require_client_or_network_credentials(self):
        settings = load_settings({}, require_network=False, require_target=False)
        self.assertIsNone(settings.target_exe)
        self.assertIsNone(settings.token)

    def test_only_one_active_capture_or_flush_owns_a_state_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            with StateLock(Path(directory)):
                with self.assertRaises(ConfigurationError):
                    with StateLock(Path(directory)):
                        self.fail('second lock must not be acquired')
            with StateLock(Path(directory)):
                pass


class FramingTests(unittest.TestCase):
    def test_raw_and_frida_wrapped_records_decode_without_tool_noise(self):
        payload = {'event_key': 'one', 'text': '任意新消息'}
        line = 'TATO_TEXT_EVENT:' + json.dumps(payload, ensure_ascii=False)
        self.assertEqual(parse_frame(line), ('event', payload))
        self.assertEqual(parse_frame(json.dumps({'type': 'log', 'payload': line})), ('event', payload))
        self.assertEqual(parse_frame('TATO_LISTENER_READY'), ('ready', {}))
        self.assertEqual(parse_frame('TATO_LISTENER_READY:{"running":true}'), ('ready', {'running': True}))
        self.assertEqual(parse_frame('tool prompt'), ('ignore', {}))
        with self.assertRaises(CaptureError):
            parse_frame('TATO_TEXT_EVENT:{bad-json}')
        with self.assertRaises(CaptureError):
            parse_frame(json.dumps({'type': 'error', 'description': 'private-data'}))

    def test_adapter_uses_native_identity_when_verified_and_omits_unverified_fields(self):
        namespace = uuid.uuid4().hex
        adapter = EventAdapter(namespace, 'fallback', attachment_id='first')
        event = {'event_key': 'event-1', 'text': ' 原文\n', 'conversation_id': 'chat:42',
                 'message_id': '37', 'sender': '123'}
        result = adapter.convert(event)
        self.assertEqual(result['conversation_id'], 'tatotalk:' + namespace + ':chat:42')
        self.assertEqual(result['message_id'], 'message:37')
        self.assertEqual(result['text'], ' 原文\n')
        self.assertEqual(result['sender'], '123')
        self.assertNotIn('timestamp', result)
        self.assertNotIn('event_key', result)
        self.assertEqual(adapter.convert(event), result)

    def test_same_text_independent_events_stay_distinct_and_replays_stay_stable(self):
        namespace = uuid.uuid4().hex
        adapter = EventAdapter(namespace, 'stream', attachment_id='first')
        first = adapter.convert({'event_key': '1', 'text': 'same'})
        self.assertEqual(first, adapter.convert({'event_key': '1', 'text': 'same'}))
        second = adapter.convert({'event_key': '2', 'text': 'same'})
        self.assertNotEqual(first['message_id'], second['message_id'])
        reattached = EventAdapter(namespace, 'stream', attachment_id='second')
        self.assertNotEqual(first['message_id'], reattached.convert({'event_key': '1', 'text': 'same'})['message_id'])

    def test_invalid_event_is_rejected_without_truncating_or_echoing_text(self):
        adapter = EventAdapter(uuid.uuid4().hex, 'stream')
        for event in ({'event_key': '1', 'text': ' '}, {'event_key': '1', 'text': 'x' * 65537},
                      {'text': 'missing-key'}, {'event_key': '1', 'text': 'private', 'conversation_id': 'fake'}):
            with self.subTest(size=len(str(event))), self.assertRaises(CaptureError) as caught:
                adapter.convert(event)
            self.assertNotIn('private', str(caught.exception))

    def test_synthetic_helper_stops_on_stdin_eof_and_never_terminates_an_external_client(self):
        source = ('import json,sys\n'
                  'print("TATO_LISTENER_READY",flush=True)\n'
                  'print("TATO_TEXT_EVENT:"+json.dumps({"event_key":"one","text":"synthetic"}),flush=True)\n'
                  'sys.stdin.read()\n')
        helper = subprocess.Popen([sys.executable, '-u', '-c', source], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8')
        stop = threading.Event()
        records = []
        def receive(event):
            records.append(event)
            stop.set()
        consume_process(helper, stop, receive, ready_timeout=2, heartbeat_timeout=2)
        self.assertEqual(records, [{'event_key': 'one', 'text': 'synthetic'}])
        self.assertEqual(helper.poll(), 0)

    def test_keyboard_interrupt_drains_already_emitted_frames_before_detach(self):
        source = ('import json,sys\n'
                  'print("TATO_LISTENER_READY",flush=True)\n'
                  'for key in ("one","two"):\n'
                  ' print("TATO_TEXT_EVENT:"+json.dumps({"event_key":key,"text":"synthetic"}),flush=True)\n'
                  'sys.stdin.read()\n')
        helper = subprocess.Popen([sys.executable, '-u', '-c', source], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8')
        stop = threading.Event()
        records = set()
        interrupted = False
        def receive(event):
            nonlocal interrupted
            records.add(event['event_key'])
            if not interrupted:
                interrupted = True
                time.sleep(0.05)
                raise KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            consume_process(helper, stop, receive, ready_timeout=2, heartbeat_timeout=2)
        self.assertTrue(stop.is_set())
        self.assertEqual(records, {'one', 'two'})
        self.assertEqual(helper.poll(), 0)


class ServiceTests(unittest.TestCase):
    def test_namespace_survives_restart_and_corruption_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            first = state_namespace(state)
            self.assertEqual(first, state_namespace(state))
            uuid.UUID(first)
            (state / 'namespace.txt').write_text('invalid')
            with self.assertRaises(ConfigurationError):
                state_namespace(state)

    def test_auth_failure_stops_worker_and_capture_without_printing_private_data(self):
        class FakeOutbox:
            def deliver_one(self, client):
                return 'auth_blocked'
            def stats(self):
                return {'pending': 1, 'delivered': 0, 'failed': 0}
        stop = threading.Event()
        events = []
        errors = []
        run_sender(FakeOutbox(), object(), stop, events.append, errors)
        self.assertTrue(stop.is_set())
        self.assertEqual(errors, ['authentication'])
        self.assertEqual(events[0]['event'], 'delivery')
        self.assertNotIn('token', json.dumps(events))

    def test_logging_failure_cannot_leave_capture_running_after_auth_rejection(self):
        class FakeOutbox:
            def deliver_one(self, client):
                return 'auth_blocked'
            def stats(self):
                return {'pending': 1}
        def broken_reporter(record):
            raise BrokenPipeError('closed output')
        stop = threading.Event()
        run_sender(FakeOutbox(), object(), stop, broken_reporter, [])
        self.assertTrue(stop.is_set())

    def test_cli_status_reads_only_local_state_without_network_or_client(self):
        with tempfile.TemporaryDirectory() as directory:
            env = {key: value for key, value in os.environ.items() if not key.startswith('TATO_')}
            env['TATO_STATE_DIR'] = directory
            result = subprocess.run([sys.executable, '-B', '-m', 'tatocatch', 'status'],
                                    capture_output=True, text=True, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['pending'], 0)


if __name__ == '__main__':
    unittest.main()
