# tests/conftest.py
#
# Tests run on SQLite (in memory) by default. `pytest --db=postgres` runs the
# same suite against PostgreSQL, using TEST_DATABASE_URI from the environment
# or from .env. In both cases the schema comes from the migrations, not from
# the models, so the tests exercise exactly what `flask db upgrade` produces.
import copy
import os

import pytest
import sqlalchemy as sa
from dotenv import dotenv_values
from flask_migrate import upgrade

from app import create_app
from extensions import db

UPLOAD_TOKEN = "test-upload-token"


def pytest_addoption(parser):
    parser.addoption(
        "--db",
        choices=["sqlite", "postgres"],
        default="sqlite",
        help="database backend for tests (postgres needs TEST_DATABASE_URI)",
    )


def pytest_report_header(config):
    return f"database backend: {config.getoption('--db')}"


@pytest.fixture(scope="session")
def database_uri(request):
    if request.config.getoption("--db") == "sqlite":
        return "sqlite://"

    uri = os.getenv("TEST_DATABASE_URI") or dotenv_values(".env").get("TEST_DATABASE_URI")
    if not uri:
        pytest.exit("--db=postgres needs TEST_DATABASE_URI (environment or .env)", returncode=2)

    # Every test truncates all tables afterwards, so refuse to run against
    # anything that doesn't look like a dedicated test database.
    db_name = sa.engine.make_url(uri).database or ""
    if not db_name.endswith("_test"):
        pytest.exit(f"refusing to use database {db_name!r}: name must end with '_test'")

    # Start every test session from an empty schema, so the migrations really
    # run from scratch instead of finding tables left over from a past run.
    engine = sa.create_engine(uri)
    with engine.begin() as conn:
        conn.execute(sa.text("DROP SCHEMA public CASCADE"))
        conn.execute(sa.text("CREATE SCHEMA public"))
    engine.dispose()
    return uri


# Smallest report the upload endpoint accepts today: one result with one
# vulnerability, modelled on real `trivy image` output.
BASE_REPORT = {
    "SchemaVersion": 2,
    "CreatedAt": "2026-11-16T16:07:52.807626425+01:00",
    "ArtifactName": "example/app:1.0",
    "ArtifactType": "container_image",
    "Metadata": {
        "OS": {"Family": "alpine", "Name": "3.24.4"},
        "ImageID": "sha256:0123456789abcdef",
        "Size": 12345,
    },
    "Results": [
        {
            "Target": "example/app:1.0 (alpine 3.24.4)",
            "Class": "os-pkgs",
            "Type": "alpine",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2026-0001",
                    "PkgName": "openssl",
                    "InstalledVersion": "3.5.0-r0",
                    "FixedVersion": "3.5.1-r0",
                    "Severity": "HIGH",
                    "Title": "openssl: example issue",
                    "References": ["https://example.com/a", "https://example.com/b"],
                }
            ],
        }
    ],
}


def _truncate_all_tables():
    # Leave the schema (and alembic_version) in place, wipe only the data.
    tables = ", ".join(f'"{t.name}"' for t in db.metadata.sorted_tables)
    db.session.execute(sa.text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))
    db.session.commit()


@pytest.fixture
def app(database_uri):
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": database_uri,
            "UPLOAD_TOKEN": UPLOAD_TOKEN,
        }
    )
    with app.app_context():
        # SQLite: a brand-new in-memory database per test, migrated from zero.
        # PostgreSQL: the first test migrates the empty schema, later ones find
        # it already at head (a no-op) and only rely on the truncate below.
        upgrade()
        yield app

        db.session.rollback()
        if db.engine.dialect.name == "postgresql":
            _truncate_all_tables()
        db.session.remove()
        # Each create_app() builds its own engine; close its connections so
        # PostgreSQL doesn't run out of connection slots over a long run.
        db.engine.dispose()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def make_report():
    """Return a fresh deep copy of BASE_REPORT with top-level keys overridden."""

    def _make(**overrides):
        report = copy.deepcopy(BASE_REPORT)
        report.update(overrides)
        return report

    return _make


@pytest.fixture
def upload(client):
    """POST a report to /v1/upload with valid auth and project headers by default."""

    def _upload(payload, headers=None):
        all_headers = {"X-Access-Token": UPLOAD_TOKEN, "X-Project": "example"}
        all_headers.update(headers or {})
        # Drop headers explicitly set to None, so tests can remove a default one.
        all_headers = {k: v for k, v in all_headers.items() if v is not None}
        return client.post("/v1/upload", json=payload, headers=all_headers)

    return _upload
