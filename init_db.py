"""Create the database tables and the encrypted-file folder.

Run ``python init_db.py`` from the project folder. It is safe to run again:
existing tables and data are never changed. Like ``run.py``, it shows a short
message, not a traceback, when something is wrong.
"""

import argparse
import sqlite3
import sys
from typing import Optional, Sequence

from sqlalchemy.exc import SQLAlchemyError

from app import create_app
from app.config import ConfigError
from app.database import InitDbError, init_db


def _describe(error: SQLAlchemyError) -> str:
    """Name the failure without risking secrets (never the database URL)."""
    detail = getattr(error, "orig", None)
    if isinstance(detail, sqlite3.Error):
        return f"{type(error).__name__}: {detail}"
    return type(error).__name__


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create the database tables and the encrypted-file "
        "folder. Safe to run again."
    )
    parser.parse_args(argv)  # takes no options; anything else is an error

    try:
        report = init_db(create_app())
    except ConfigError as error:
        # Only the message is shown: ConfigError never contains secret values.
        print(
            f"Cannot initialise: invalid configuration.\n{error}",
            file=sys.stderr,
        )
        return 1
    except InitDbError as error:
        print(f"Cannot initialise: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(
            f"Cannot initialise: file system error ({error.strerror}).",
            file=sys.stderr,
        )
        return 1
    except SQLAlchemyError as error:
        print(
            f"Cannot initialise: database error ({_describe(error)}).",
            file=sys.stderr,
        )
        return 1

    if report.tables_created:
        print("Tables created: " + ", ".join(report.tables_created))
    if report.tables_existing:
        print("Tables already present: " + ", ".join(report.tables_existing))
    if report.storage_created:
        state = "created"
    elif report.storage_tightened:
        state = "already existed; permissions tightened to owner-only"
    else:
        state = "already present"
    print(f"Storage folder ({state}): {report.storage_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
