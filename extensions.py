# extensions.py
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import MetaData

# Deterministic names for every index and constraint, identical on SQLite and
# PostgreSQL. Alembic needs a name to drop or alter a constraint, and on SQLite
# (batch mode, which rebuilds the table) unnamed constraints can't be targeted
# at all. Must be in place before the baseline migration is generated.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

db = SQLAlchemy(metadata=MetaData(naming_convention=NAMING_CONVENTION))
