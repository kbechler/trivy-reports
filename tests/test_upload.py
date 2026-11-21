# tests/test_upload.py
#
# Characterization tests for POST /v1/upload: they pin down how the endpoint
# behaves today, so later refactors (migrations, new data model) can't change
# it by accident.
from datetime import datetime, timezone

import pytest

from models.reports import ScanReport, Vulnerability

# --- happy path ---


def test_upload_container_image_stores_report(upload, make_report):
    response = upload(make_report(), headers={"X-Commit": "abc123", "X-Tag": "v1.0"})

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}

    report = ScanReport.query.one()
    assert report.project == "example"
    assert report.commit == "abc123"
    assert report.tag == "v1.0"
    assert report.artifact_name == "example/app:1.0"
    assert report.artifact_type == "container_image"
    assert report.os == "alpine 3.24.4"
    assert report.image_id == "sha256:0123456789abcdef"
    assert report.size == 12345


def test_upload_stores_created_at_as_utc(request, upload, make_report):
    # Known issue (step 2.4): generated_at has no timezone, so the +01:00
    # offset from the report is lost and what's stored depends on the backend.
    # SQLite keeps the report's wall clock (16:07). PostgreSQL converts to the
    # session timezone first, and only passes here because that's UTC in the
    # test container; a server in another timezone would store yet another value.
    if request.config.getoption("--db") == "sqlite":
        request.applymarker(
            pytest.mark.xfail(strict=True, reason="SQLite stores local wall clock; step 2.4")
        )

    upload(make_report())

    stored = ScanReport.query.one().generated_at
    if stored.tzinfo is not None:
        stored = stored.astimezone(timezone.utc).replace(tzinfo=None)
    # 2026-11-16T16:07:52.807626+01:00 in the report is 15:07:52 UTC
    # (Python keeps microseconds; Trivy's nanoseconds are truncated).
    assert stored == datetime(2026, 11, 16, 15, 7, 52, 807626)


def test_upload_stores_vulnerabilities(upload, make_report):
    upload(make_report())

    vuln = Vulnerability.query.one()
    assert vuln.vuln_id == "CVE-2026-0001"
    assert vuln.pkg_name == "openssl"
    assert vuln.installed_version == "3.5.0-r0"
    assert vuln.fixed_version == "3.5.1-r0"
    assert vuln.severity == "HIGH"
    assert vuln.references == "https://example.com/a, https://example.com/b"
    assert vuln.result.report.project == "example"


def test_upload_filesystem_artifact(upload, make_report):
    response = upload(make_report(ArtifactType="filesystem", Metadata={}))

    assert response.status_code == 200
    report = ScanReport.query.one()
    assert report.artifact_type == "filesystem"
    assert report.os == ""


def test_upload_accepts_empty_results_list(upload, make_report):
    response = upload(make_report(Results=[]))

    assert response.status_code == 200
    assert ScanReport.query.count() == 1


# --- auth ---


@pytest.mark.parametrize(
    "token, message",
    [(None, "Auth token not found"), ("wrong-token", "Wrong token")],
)
def test_upload_rejects_bad_token(upload, make_report, token, message):
    response = upload(make_report(), headers={"X-Access-Token": token})

    assert response.status_code == 401
    assert response.get_json()["message"] == message
    assert ScanReport.query.count() == 0


# --- validation ---


def test_upload_requires_project_header(upload, make_report):
    response = upload(make_report(), headers={"X-Project": None})

    assert response.status_code == 400
    assert response.get_json() == {"error": "No project name"}


@pytest.mark.parametrize(
    "missing_key", ["SchemaVersion", "ArtifactName", "ArtifactType", "Results", "CreatedAt"]
)
def test_upload_rejects_missing_required_key(upload, make_report, missing_key):
    payload = make_report()
    del payload[missing_key]

    response = upload(payload)

    assert response.status_code == 400
    assert response.get_json() == {"error": "Unknown JSON structure"}


def test_upload_rejects_unknown_schema_version(upload, make_report):
    response = upload(make_report(SchemaVersion=1))

    assert response.status_code == 400
    assert response.get_json() == {"error": "Unknown JSON structure"}


def test_upload_rejects_unknown_artifact_type(upload, make_report):
    response = upload(make_report(ArtifactType="repository"))

    assert response.status_code == 400
    assert response.get_json() == {"error": "Unknown JSON structure"}


@pytest.mark.parametrize("created_at", ["not-a-date", 12345, None])
def test_upload_rejects_invalid_created_at(upload, make_report, created_at):
    response = upload(make_report(CreatedAt=created_at))

    assert response.status_code == 400
    assert response.get_json() == {"error": "Invalid CreatedAt timestamp"}
    assert ScanReport.query.count() == 0


def test_upload_rejects_empty_json_object(upload):
    response = upload({})

    assert response.status_code == 400
    assert response.get_json() == {"error": "Invalid or missing JSON"}


def test_upload_rejects_malformed_json(client):
    response = client.post(
        "/v1/upload",
        data="{not json",
        content_type="application/json",
        headers={"X-Access-Token": "test-upload-token", "X-Project": "example"},
    )

    assert response.status_code == 400
    assert response.get_json()["code"] == 400


def test_upload_rejects_non_json_content_type(client):
    response = client.post(
        "/v1/upload",
        data="hello",
        content_type="text/plain",
        headers={"X-Access-Token": "test-upload-token", "X-Project": "example"},
    )

    assert response.status_code == 415
    assert response.get_json()["code"] == 415


# --- known bugs, fixed later in the plan ---


@pytest.mark.xfail(strict=True, reason="Results: null crashes the loop; fixed in step 2.1")
def test_upload_accepts_null_results(upload, make_report):
    response = upload(make_report(Results=None))

    assert response.status_code == 200
    assert ScanReport.query.count() == 1


# --- other /v1 routes ---


def test_unknown_v1_path_returns_json_404(client):
    response = client.get("/v1/does-not-exist", headers={"X-Access-Token": "test-upload-token"})

    assert response.status_code == 404
    assert response.get_json()["code"] == 404
