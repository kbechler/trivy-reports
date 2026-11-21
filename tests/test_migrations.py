# tests/test_migrations.py
#
# The `app` fixture has already run `flask db upgrade` on an empty database,
# so these tests look at the schema the migrations actually produced.
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from flask_migrate import downgrade, upgrade

from extensions import db


def _schema_diff():
    with db.engine.connect() as conn:
        context = MigrationContext.configure(conn)
        return compare_metadata(context, db.metadata)


def test_models_match_migrations(app):
    # Fails when a model changes without a matching migration (or the other
    # way round). Fix: `flask db migrate -m "..."`, review, commit both.
    assert _schema_diff() == []


def test_migrations_are_at_single_head(app):
    with db.engine.connect() as conn:
        heads = MigrationContext.configure(conn).get_current_heads()
    assert len(heads) == 1


def test_downgrade_to_base_and_upgrade_again(app):
    downgrade(revision="base")
    with db.engine.connect() as conn:
        assert MigrationContext.configure(conn).get_current_revision() is None
        remaining = set(db.inspect(conn).get_table_names()) - {"alembic_version"}
    assert remaining == set()

    upgrade()
    assert _schema_diff() == []
