# tests/conftest.py
import copy

import pytest

from app import create_app
from extensions import db

UPLOAD_TOKEN = "test-upload-token"

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


@pytest.fixture
def app():
    # A fresh in-memory SQLite database per test: every create_app() call builds
    # its own engine, so tests can't see each other's data.
    app = create_app(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "UPLOAD_TOKEN": UPLOAD_TOKEN,
        }
    )
    with app.app_context():
        # Temporary: tables straight from the models. Step 1.5 switches this to
        # running the migrations, so tests exercise the real schema.
        db.create_all()
        yield app


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
