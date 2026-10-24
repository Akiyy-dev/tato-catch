"""Capture and delivery run independently; the outbox is the durability boundary."""
import json
import os
from pathlib import Path
import threading
import uuid

from .capture import CaptureError, EventAdapter, run_native_session
from .config import ConfigurationError, StateLock
from .delivery import IngestClient, Outbox


def emit(record):
    print(json.dumps(record, ensure_ascii=True, sort_keys=True), flush=True)


def state_namespace(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / 'namespace.txt'
    if not path.exists():
        value = uuid.uuid4().hex
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(descriptor, 'w', encoding='ascii') as stream:
                stream.write(value)
    try:
        return uuid.UUID(path.read_text(encoding='ascii').strip()).hex
    except (OSError, ValueError, UnicodeError):
        raise ConfigurationError('Invalid capture namespace; preserve the state directory and repair configuration') from None


def run_sender(outbox, client, stop, reporter=emit, errors=None):
    errors = [] if errors is None else errors
    while not stop.is_set():
        try:
            outcome = outbox.deliver_one(client)
            if outcome == 'auth_blocked':
                errors.append('authentication')
                stop.set()
            if outcome != 'idle':
                reporter({'event': 'delivery', 'state': outcome, **outbox.stats()})
            if outcome == 'auth_blocked':
                return
            if outcome in {'idle', 'retry'}:
                stop.wait(0.5)
        except Exception:
            errors.append('outbox_delivery')
            stop.set()
            try:
                reporter({'event': 'error', 'category': 'outbox_delivery', 'queued_data_retained': True})
            except Exception:
                pass
            return


def listen(settings, *, pid=None, capture_only=False, reporter=emit):
    stop = threading.Event()
    errors = []
    with StateLock(settings.state_dir):
        namespace = state_namespace(settings.state_dir)
        outbox = Outbox(settings.state_dir / 'outbox.sqlite3')
        worker = None
        try:
            if not capture_only:
                client = IngestClient(settings.endpoint, settings.token, timeout=settings.http_timeout)
                outbox.bind_endpoint(client.endpoint)
                worker = threading.Thread(target=run_sender, args=(outbox, client, stop, reporter, errors),
                                          name='ingest-sender', daemon=True)
                worker.start()
            reporter({'event': 'starting', 'capture_only': capture_only, **outbox.stats()})
            retry_delay = 1
            while not stop.is_set():
                adapter = EventAdapter(namespace, settings.conversation_id, settings.conversation_name)
                def ready():
                    nonlocal retry_delay
                    retry_delay = 1
                    reporter({'event': 'ready', 'capture_only': capture_only})
                def receive(event):
                    try:
                        payload = adapter.convert(event)
                        outbox.enqueue(payload)
                    except Exception:
                        errors.append('capture_persistence')
                        stop.set()
                        raise CaptureError('Cannot persist a captured message; capture stopped') from None
                try:
                    run_native_session(settings.target_exe, stop, receive, requested_pid=pid,
                                       include_outgoing=settings.include_outgoing, on_ready=ready)
                except CaptureError as error:
                    if not stop.is_set():
                        if not error.retryable:
                            errors.append('capture_stopped')
                            reporter({'event': 'error', 'category': 'capture_stopped', 'reason': str(error)})
                            stop.set()
                            break
                        reporter({'event': 'capture_reconnecting', 'reason': str(error), 'retry_in_seconds': retry_delay})
                        stop.wait(retry_delay)
                        retry_delay = min(30, retry_delay * 2)
        except KeyboardInterrupt:
            reporter({'event': 'stopping'})
        finally:
            stop.set()
            if worker:
                worker.join(timeout=settings.http_timeout + 5)
            summary = outbox.stats()
            if not worker or not worker.is_alive():
                outbox.close()
            reporter({'event': 'stopped', 'queued_data_retained': True, **summary})
    return 2 if errors else 0


def flush(settings, *, retry_failed=False, test_text=None, reporter=emit):
    with StateLock(settings.state_dir):
        outbox = Outbox(settings.state_dir / 'outbox.sqlite3')
        try:
            client = IngestClient(settings.endpoint, settings.token, timeout=settings.http_timeout)
            outbox.bind_endpoint(client.endpoint)
            if retry_failed:
                outbox.retry_failed()
            if test_text is not None:
                outbox.enqueue({'message_id': 'test:' + uuid.uuid4().hex,
                    'conversation_id': settings.conversation_id, 'text': test_text})
            while True:
                outcome = outbox.deliver_one(client)
                if outcome != 'idle':
                    reporter({'event': 'delivery', 'state': outcome})
                if outcome in {'idle', 'retry', 'auth_blocked'}:
                    break
            summary = outbox.stats()
            reporter({'event': 'queue_status', **summary})
            return 2 if summary.get('pending', 0) or summary.get('failed', 0) else 0
        finally:
            outbox.close()
