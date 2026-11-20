# tests/test_schema.py
#
# Guards on the model metadata itself, independent of any database.
from extensions import db

# PostgreSQL silently truncates identifiers longer than this, which would make
# the name in the database differ from the one in the models and migrations.
POSTGRES_MAX_IDENTIFIER_LENGTH = 63


def _named_objects():
    for table in db.metadata.sorted_tables:
        for constraint in table.constraints:
            yield table.name, constraint
        for index in table.indexes:
            yield table.name, index


def test_every_constraint_and_index_has_a_name(app):
    unnamed = [f"{table}: {type(obj).__name__}" for table, obj in _named_objects() if not obj.name]
    assert unnamed == []


def test_names_fit_postgres_identifier_limit(app):
    too_long = [
        obj.name for _, obj in _named_objects() if len(obj.name) > POSTGRES_MAX_IDENTIFIER_LENGTH
    ]
    assert too_long == []


def test_naming_convention_is_applied(app):
    user = db.metadata.tables["user"]
    names = {c.name for c in user.constraints}
    assert names == {"pk_user", "uq_user_username"}
