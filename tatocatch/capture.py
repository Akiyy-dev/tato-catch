"""Version-bound native capture host and bounded Frida console framing."""
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
EXE_HASH = '76c9c41b7dfac2861f3d30aea53e7a6261b136c610acddd87097dae8f1a6de58'
HELPER_HASH = 'e2fac3a19b7ad0f9e00e81f3bf10d1090c1471a9b6fb22efbffa21e3f29ee60e'
MAX_LINE = 1024 * 1024


class CaptureError(ValueError):
    def __init__(self, message, *, retryable=True):
        super().__init__(message)
        self.retryable = retryable


def parse_frame(line):
    if len(line) > MAX_LINE:
        raise CaptureError('Capture frame exceeds the size limit')
    line = line.strip()
    if line.startswith('{'):
        try:
            envelope = json.loads(line)
        except (ValueError, RecursionError):
            return 'ignore', {}
        if isinstance(envelope, dict) and envelope.get('type') == 'error':
            raise CaptureError('The native listener reported an error')
        if isinstance(envelope, dict) and envelope.get('type') == 'log':
            line = envelope.get('payload', '')
    if not isinstance(line, str):
        return 'ignore', {}
    if line == 'TATO_LISTENER_READY':
        return 'ready', {}
    for marker, kind in [('TATO_LISTENER_READY:', 'ready'), ('TATO_TEXT_EVENT:', 'event'), ('TATO_LISTENER_HEARTBEAT:', 'heartbeat'),
                         ('TATO_LISTENER_STOPPED:', 'stopped')]:
        if line.startswith(marker):
            try:
                payload = json.loads(line[len(marker):])
            except (ValueError, RecursionError):
                raise CaptureError('Malformed capture record') from None
            if not isinstance(payload, dict):
                raise CaptureError('Invalid capture record type')
            return kind, payload
    return 'ignore', {}


class EventAdapter:
    def __init__(self, namespace, conversation_id, conversation_name=None, *, attachment_id=None):
        self.namespace = uuid.UUID(str(namespace))
        self.conversation_id = conversation_id
        self.conversation_name = conversation_name
        self.attachment_id = attachment_id or uuid.uuid4().hex

    def convert(self, event):
        if not isinstance(event, dict):
            raise CaptureError('Capture event must be an object')
        text = event.get('text')
        key = event.get('event_key')
        if (not isinstance(text, str) or not text.strip() or len(text) > 65536
                or not isinstance(key, str) or not key or len(key) > 256):
            raise CaptureError('Invalid or oversized capture text/event identity')
        peer = event.get('conversation_id')
        if peer is not None and (not isinstance(peer, str) or not re.fullmatch(r'(?:user|chat|channel):[1-9][0-9]{0,19}', peer)):
            raise CaptureError('Invalid verified conversation identity')
        conversation = 'tatotalk:' + self.namespace.hex + ':' + peer if peer else self.conversation_id
        native_id = event.get('message_id')
        if native_id is not None and (not isinstance(native_id, str) or not re.fullmatch(r'[1-9][0-9]{0,19}', native_id)):
            raise CaptureError('Invalid verified native message identity')
        message_id = ('message:' + native_id) if native_id and peer else 'capture:' + uuid.uuid5(
            self.namespace, self.attachment_id + '/' + key).hex
        payload = {'message_id': message_id, 'conversation_id': conversation, 'text': text}
        if self.conversation_name is not None:
            payload['conversation_name'] = self.conversation_name
        sender = event.get('sender')
        if sender is not None:
            if not isinstance(sender, str) or not re.fullmatch(r'[1-9][0-9]{0,19}', sender):
                raise CaptureError('Invalid verified sender identity')
            payload['sender'] = sender
        # Server receive time is deliberately omitted and remains omitted on retries.
        return payload


def stop_helper(process):
    """Only handles the helper returned by this host's own Popen call."""
    if process.stdin:
        try:
            process.stdin.close()
        except (OSError, BrokenPipeError):
            pass
    try:
        process.wait(timeout=12)
    except subprocess.TimeoutExpired:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def consume_process(process, stop, on_event, *, on_ready=None, ready_timeout=15, heartbeat_timeout=35):
    records = queue.Queue(maxsize=1024)
    ended = threading.Event()
    reader_errors = []

    def read_output():
        try:
            while True:
                line = process.stdout.readline(MAX_LINE + 1)
                if not line:
                    break
                if len(line) > MAX_LINE:
                    raise CaptureError('Capture frame exceeds the size limit')
                records.put(line, timeout=2)
        except (OSError, ValueError, queue.Full, CaptureError):
            reader_errors.append(True)
        finally:
            ended.set()

    reader = threading.Thread(target=read_output, name='capture-frames', daemon=True)
    reader.start()
    ready = False
    in_flight = None
    started = last_activity = time.monotonic()
    try:
        while not stop.is_set():
            if reader_errors:
                raise CaptureError('Capture output failed or the local consumer is overloaded', retryable=False)
            try:
                line = records.get(timeout=0.1)
            except queue.Empty:
                if ended.is_set():
                    raise CaptureError('The native capture helper disconnected')
                now = time.monotonic()
                if not ready and now - started > ready_timeout:
                    raise CaptureError('The native listener did not become ready')
                if ready and now - last_activity > heartbeat_timeout:
                    raise CaptureError('The native listener heartbeat expired')
                continue
            kind, payload = parse_frame(line)
            if kind == 'ready':
                ready = True
                last_activity = time.monotonic()
                if on_ready:
                    on_ready()
            elif kind in {'event', 'heartbeat'}:
                if not ready:
                    raise CaptureError('Capture event arrived before readiness')
                last_activity = time.monotonic()
                if kind == 'event':
                    in_flight = payload
                    on_event(payload)
                    in_flight = None
            elif kind == 'stopped':
                raise CaptureError('The native listener stopped')
    except KeyboardInterrupt:
        stop.set()
        raise
    finally:
        # Drain while the helper detaches: waiting first could fill the bounded queue.
        cleanup = threading.Thread(target=stop_helper, args=(process,), daemon=True)
        cleanup.start()
        drain_failure = None
        try:
            if in_flight is not None:
                try:
                    on_event(in_flight)  # Stable IDs make an interrupted commit safe to replay.
                except Exception as error:
                    drain_failure = error
            deadline = time.monotonic() + 25
            while cleanup.is_alive() or not ended.is_set() or not records.empty():
                # A slow but healthy disk must not time out already buffered writes.
                if time.monotonic() > deadline and records.empty():
                    drain_failure = drain_failure or CaptureError('Capture shutdown did not drain all output', retryable=False)
                    break
                try:
                    line = records.get(timeout=0.1)
                except queue.Empty:
                    continue
                try:
                    kind, payload = parse_frame(line)
                    if kind == 'event' and drain_failure is None:
                        on_event(payload)
                except Exception as error:
                    drain_failure = drain_failure or error
            cleanup.join(timeout=1)
            reader.join(timeout=1)
        finally:
            if process.stdout:
                process.stdout.close()
        if drain_failure is not None:
            stop.set()
            raise CaptureError('Cannot persist all capture frames during shutdown', retryable=False) from None


def _checked_digest(path, expected):
    try:
        with path.open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    except OSError:
        raise CaptureError('Required client or helper executable is unavailable', retryable=False) from None
    if actual != expected:
        raise CaptureError('Unsupported client or helper executable hash', retryable=False)


def process_image(pid):
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        raise CaptureError('The selected client process is unavailable')
    try:
        name = ctypes.create_unicode_buffer(32768)
        count = wintypes.DWORD(len(name))
        if not kernel.QueryFullProcessImageNameW(handle, 0, name, ctypes.byref(count)):
            raise CaptureError('Cannot verify the selected process executable')
        return Path(name.value).resolve()
    finally:
        kernel.CloseHandle(handle)


def find_target_pid(target, requested=None):
    if os.name != 'nt' or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise CaptureError('Live capture requires Windows x64')
    target = Path(target).resolve(strict=True)
    if requested is not None:
        if requested <= 0 or os.path.normcase(str(process_image(requested))) != os.path.normcase(str(target)):
            raise CaptureError('PID does not match the configured executable')
        return requested
    class Entry(ctypes.Structure):
        _fields_ = [('dwSize', wintypes.DWORD), ('cntUsage', wintypes.DWORD),
                    ('th32ProcessID', wintypes.DWORD), ('th32DefaultHeapID', ctypes.c_size_t),
                    ('th32ModuleID', wintypes.DWORD), ('cntThreads', wintypes.DWORD),
                    ('th32ParentProcessID', wintypes.DWORD), ('pcPriClassBase', wintypes.LONG),
                    ('dwFlags', wintypes.DWORD), ('szExeFile', wintypes.WCHAR * 260)]
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    kernel.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    snapshot = kernel.CreateToolhelp32Snapshot(2, 0)
    if snapshot == ctypes.c_void_p(-1).value:
        raise CaptureError('Cannot enumerate the client process')
    matches = []
    try:
        entry = Entry()
        entry.dwSize = ctypes.sizeof(entry)
        valid = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
        while valid:
            if entry.szExeFile.lower() == target.name.lower():
                try:
                    if os.path.normcase(str(process_image(entry.th32ProcessID))) == os.path.normcase(str(target)):
                        matches.append(entry.th32ProcessID)
                except CaptureError:
                    pass
            valid = kernel.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel.CloseHandle(snapshot)
    if len(matches) != 1:
        raise CaptureError('Exactly one matching logged-in client must run; use --pid when needed')
    return matches[0]


def run_native_session(target, stop, on_event, *, requested_pid=None, include_outgoing=False, on_ready=None):
    target = Path(target).resolve(strict=True)
    if target.name.lower() != 'tatotalk.exe':
        raise CaptureError('The configured executable must be Tatotalk.exe')
    _checked_digest(target, EXE_HASH)
    helper = ROOT / 'research/tools/frida-inject-17.24.3-windows-x86_64.exe'
    _checked_digest(helper, HELPER_HASH)
    pid = find_target_pid(target, requested_pid)
    source = (ROOT / 'research/windows-text-listener.js').read_text(encoding='utf-8')
    if source.count('/*TARGET_EXE*/null') != 1 or source.count('/*INCLUDE_OUTGOING*/false') != 1:
        raise CaptureError('Listener configuration placeholders changed')
    source = source.replace('/*TARGET_EXE*/null', json.dumps(str(target), ensure_ascii=True), 1)
    source = source.replace('/*INCLUDE_OUTGOING*/false', 'true' if include_outgoing else 'false', 1)
    with tempfile.TemporaryDirectory(prefix='tatocatch-listener-') as directory:
        script = Path(directory) / 'listener.js'
        script.write_text(source, encoding='utf-8')
        process = subprocess.Popen([str(helper), '-p', str(pid), '-s', str(script), '-i', '-R', 'qjs'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding='utf-8', errors='replace', creationflags=subprocess.CREATE_NO_WINDOW)
        consume_process(process, stop, on_event, on_ready=on_ready)
