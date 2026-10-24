"""Local runtime configuration. Secret values are never part of public examples."""
from dataclasses import dataclass, field
import json
import os
from pathlib import Path


class ConfigurationError(ValueError):
    pass


@dataclass(frozen=True)
class Settings:
    target_exe: str | None
    endpoint: str | None = field(repr=False)
    token: str | None = field(repr=False)
    state_dir: Path
    conversation_id: str = 'tatotalk-stream'
    conversation_name: str | None = None
    http_timeout: float = 30
    include_outgoing: bool = False


def load_settings(env=None, config_path=None, *, require_network=True, require_target=True):
    env = os.environ if env is None else env
    allowed = {'target_exe', 'ingest_url', 'ingest_token', 'state_dir', 'conversation_id',
               'conversation_name', 'http_timeout', 'include_outgoing'}
    values = {}
    if config_path:
        try:
            values = json.loads(Path(config_path).read_text(encoding='utf-8-sig'))
        except (OSError, ValueError):
            raise ConfigurationError('Cannot read a valid local JSON configuration') from None
        if not isinstance(values, dict) or not set(values).issubset(allowed):
            raise ConfigurationError('Unknown configuration field')
    for key in allowed:
        value = env.get('TATO_' + key.upper())
        if value is not None:
            values[key] = value
    for key in ('target_exe', 'ingest_url', 'ingest_token', 'state_dir', 'conversation_id', 'conversation_name'):
        if key in values and values[key] is not None and not isinstance(values[key], str):
            raise ConfigurationError('Configuration string field has an invalid type')
    endpoint = values.get('ingest_url') or None
    if endpoint and not endpoint.rstrip('/').endswith('/api/ingest/v1/messages'):
        endpoint = endpoint.rstrip('/') + '/api/ingest/v1/messages'
    token = values.get('ingest_token') or None
    target = values.get('target_exe') or None
    if require_network and (not endpoint or not token):
        raise ConfigurationError('Set TATO_INGEST_URL and TATO_INGEST_TOKEN, or use a private config file')
    if token and (not token.startswith('tgfi_') or any(character.isspace() for character in token)):
        raise ConfigurationError('Use a valid message-ingestion tgfi_ token')
    if require_target and not target:
        raise ConfigurationError('Set TATO_TARGET_EXE or pass --target-exe')
    conversation = values.get('conversation_id', 'tatotalk-stream')
    name = values.get('conversation_name')
    if not conversation or not conversation.strip() or len(conversation) > 128:
        raise ConfigurationError('Logical conversation ID must contain 1 to 128 characters')
    if name is not None and len(name) > 256:
        raise ConfigurationError('Logical conversation name exceeds 256 characters')
    try:
        timeout = float(values.get('http_timeout', 30))
        if not 1 <= timeout <= 120:
            raise ValueError
    except (TypeError, ValueError):
        raise ConfigurationError('HTTP timeout must be between 1 and 120 seconds') from None
    outgoing = values.get('include_outgoing', False)
    if isinstance(outgoing, str) and outgoing.lower() in {'true', 'false', '1', '0'}:
        outgoing = outgoing.lower() in {'true', '1'}
    if not isinstance(outgoing, bool):
        raise ConfigurationError('include_outgoing must be boolean')
    return Settings(target, endpoint, token, Path(values.get('state_dir') or '.local/state').resolve(),
                    conversation, name, timeout, outgoing)


class StateLock:
    """An OS lock is released even after a crash; the lock file can remain."""
    def __init__(self, directory):
        self.directory = Path(directory)
        self.stream = None

    def __enter__(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        self.stream = (self.directory / 'capture.lock').open('a+b')
        try:
            self.stream.seek(0, 2)
            if self.stream.tell() == 0:
                self.stream.write(b'1')
                self.stream.flush()
            self.stream.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.stream.close()
            self.stream = None
            raise ConfigurationError('This state directory is already in use') from None
        return self

    def __exit__(self, *exc):
        if self.stream is not None:
            self.stream.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
            self.stream.close()
            self.stream = None
