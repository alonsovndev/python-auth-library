"""Optional PostgreSQL/SQLAlchemy adapters for the pyauthkit stores.

Importing this package requires the ``[sqlalchemy]`` extra. The tables are independent of
any host schema (string user identifiers, no foreign keys), so they can live in the same
database without coupling to the host's ``users`` table.
"""

from pyauthkit.sqlalchemy.models import Base
from pyauthkit.sqlalchemy.repositories import SqlCodeStore, SqlLockoutStore, SqlRevocationStore

__all__ = ["Base", "SqlCodeStore", "SqlLockoutStore", "SqlRevocationStore"]
