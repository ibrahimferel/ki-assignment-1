"""Entry point for the development server.

Start the application with ``python run.py`` (optionally ``--port 8080``).
This is the only supported way to start the server: it uses the strict
settings validated in ``app/config.py`` and shows a short message, not a
traceback, when the configuration is invalid.
"""

import argparse
import sys
from typing import Optional, Sequence

from app import create_app
from app.config import ConfigError

# Listen on this machine only: the development server is not hardened.
HOST = "127.0.0.1"
# Not 5000: macOS often reserves it for the AirPlay Receiver service.
DEFAULT_PORT = 8000


def _port_number(text: str) -> int:
    try:
        port = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a whole number") from None
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("must be between 1 and 65535")
    return port


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run the development server.")
    parser.add_argument(
        "--port",
        type=_port_number,
        default=DEFAULT_PORT,
        help=f"port to listen on (default: {DEFAULT_PORT})",
    )
    args = parser.parse_args(argv)

    try:
        flask_app = create_app()
    except ConfigError as error:
        # Only the message is shown: ConfigError never contains secret values.
        print(
            f"Cannot start: invalid configuration.\n{error}", file=sys.stderr
        )
        return 1

    # debug=flask_app.debug makes our strictly validated FLASK_DEBUG the final
    # word (app.run() would otherwise re-read it loosely). load_dotenv=False
    # stops Flask from loading .env/.flaskenv a second time: Config already
    # read the project's .env.
    flask_app.run(
        host=HOST, port=args.port, debug=flask_app.debug, load_dotenv=False
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
