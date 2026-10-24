"""Run ``python -m tatocatch --help`` for local configuration and commands."""
import argparse
import os
import sys

from .config import ConfigurationError, load_settings
from .delivery import DeliveryError, Outbox
from .service import emit, flush, listen


def main(argv=None):
    parser = argparse.ArgumentParser(description='Continuous Windows TatoTalk text capture and remote ingestion')
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('listen', 'status', 'flush', 'send-test'):
        command = commands.add_parser(name)
        command.add_argument('--config', help='Private local JSON configuration file')
        if name == 'listen':
            command.add_argument('--target-exe', help='Supported official client executable')
            command.add_argument('--pid', type=int, help='Pin a PID; omit for process rediscovery')
            command.add_argument('--include-outgoing', action='store_true', help='Also capture messages sent by this account')
            command.add_argument('--capture-only', action='store_true', help='Persist locally without network delivery')
        if name == 'flush':
            command.add_argument('--retry-failed', action='store_true', help='Explicitly retry retained permanent failures')
        if name == 'send-test':
            command.add_argument('--text', default='Tato Catch remote push test')
    args = parser.parse_args(argv)
    env = dict(os.environ)
    if getattr(args, 'target_exe', None):
        env['TATO_TARGET_EXE'] = args.target_exe
    if getattr(args, 'include_outgoing', False):
        env['TATO_INCLUDE_OUTGOING'] = 'true'
    try:
        network = args.command != 'status' and not getattr(args, 'capture_only', False)
        settings = load_settings(env, args.config, require_network=network, require_target=args.command == 'listen')
        if args.command == 'status':
            outbox = Outbox(settings.state_dir / 'outbox.sqlite3')
            try:
                emit(outbox.stats())
                return 0
            finally:
                outbox.close()
        if args.command == 'listen':
            return listen(settings, pid=args.pid, capture_only=args.capture_only)
        return flush(settings, retry_failed=getattr(args, 'retry_failed', False),
                     test_text=args.text if args.command == 'send-test' else None)
    except (ConfigurationError, DeliveryError, ValueError, OSError):
        # Exception messages may carry caller data or OS paths; keep diagnostics categorical.
        emit({'event': 'error', 'category': 'configuration_or_storage',
              'hint': 'Check private config, supported client, endpoint binding and local disk access'})
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == '__main__':
    sys.exit(main())
