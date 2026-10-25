"""Safe handling of the ``next`` address used after login.

``next`` comes from the query string, so an attacker can put anything in it.
Only a plain path on this same site is accepted; everything else is refused
and the caller falls back to the home page. Refusing is safer than trying to
clean the value up.
"""

from urllib.parse import urlsplit

__all__ = ["MAX_NEXT_LENGTH", "safe_next_url"]

MAX_NEXT_LENGTH = 2048


def safe_next_url(target):
    """Return ``target`` unchanged if it is a safe local path, else ``None``.

    Accepted: a string that starts with one "/" and then continues with
    printable ASCII, for example ``/files?id=3``. Refused, among others:

    * ``//host``, ``///host`` and ``/\\host`` (browsers read these as a host),
    * ``https://host`` and ``javascript:...`` (anything with a scheme),
    * tabs, newlines and other control characters or spaces (browsers delete
      tabs and newlines, so ``/<tab>/host`` would become ``//host``),
    * backslashes, non-ASCII text and a doubled slash inside the path.
    """
    if not isinstance(target, str):
        return None
    if not 0 < len(target) <= MAX_NEXT_LENGTH:
        return None
    if not target.isascii() or not target.isprintable() or " " in target:
        return None
    if "\\" in target:
        return None
    if not target.startswith("/") or target.startswith("//"):
        return None
    parts = urlsplit(target)
    if parts.scheme or parts.netloc or "//" in parts.path:
        return None
    return target
