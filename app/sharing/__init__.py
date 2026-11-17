"""Sharing blueprint registered by create_app; see docs/acuan_member3.md.

The factory's global CSRFProtect covers POST requests. JSON clients send
X-CSRFToken. Importing this package does not create or migrate tables.
"""

from app.sharing.routes import sharing_bp

__all__ = ["sharing_bp"]
