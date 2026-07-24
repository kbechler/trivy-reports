# Trivy Reports

A small self-hosted service for collecting [Trivy](https://github.com/aquasecurity/trivy) scan
reports from CI pipelines and browsing them in a web UI.

It exposes two things:

- **`POST /v1/upload`** — a token-protected API endpoint that CI jobs `curl` a Trivy JSON report
  to, right after running `trivy image` or `trivy fs`.
- **`/ui`** — a Basic Auth-protected web UI to list uploaded reports (filterable by project) and
  drill into vulnerabilities, misconfigurations, and secret findings for a single scan.

Reports are parsed and stored in a relational database (SQLite by default), so instead of
scrolling through raw JSON in a build log, you get a searchable history of scans per project.

## Features

- Ingests both `filesystem` and `container_image` Trivy scan types.
- Stores vulnerabilities, misconfigurations, and secret findings as separate, queryable records.
- Web UI with a project filter and per-report drill-down, sorted by severity
  (Critical → High → Medium → Low).
- Stateless app process — all state lives in the database, so the container can be recreated
  freely as long as the volume/DB is persisted.

## Architecture

```
.
├── app.py               # Flask application factory
├── wsgi.py              # Gunicorn entrypoint (imports create_app())
├── auth.py              # before_request hook: token auth for /v1, Basic Auth for /ui
├── errors.py            # JSON error handlers (400/404/405/415)
├── extensions.py        # shared Flask-SQLAlchemy instance
├── api/
│   ├── v1/              # upload API blueprint
│   └── ui/              # web UI blueprint
├── models/
│   └── reports.py       # ScanReport / ScanResult / Vulnerability / Misconfiguration / SecretFinding
├── templates/           # Jinja2 templates for the UI
└── Dockerfile
```

Two Flask blueprints, one shared SQLAlchemy model layer, one auth middleware that branches on
the URL prefix (`/v1` vs `/ui`). Gunicorn binds to `127.0.0.1:8000` inside the container — it's
meant to sit behind a reverse proxy that terminates TLS, not be exposed directly.

## Getting started

### Prerequisites

- Docker (recommended), or Python 3.12+ if running locally.
- [Trivy](https://github.com/aquasecurity/trivy) installed wherever you generate scan reports
  (typically a CI runner).

### Configuration

Copy `.env.example` to `.env` and fill in real values:

| Variable                    | Description                                                       |
|-----------------------------|---------------------------------------------------------------------|
| `SQLALCHEMY_DATABASE_URI`   | DB connection string. Defaults to a local SQLite file.              |
| `UPLOAD_TOKEN`              | Shared secret required in the `X-Access-Token` header for uploads.  |
| `ADMIN_PASSWORD`            | Password for the `admin` user on the `/ui` Basic Auth prompt.        |
| `FLASK_ENV` / `FLASK_DEBUG` | Standard Flask environment flags.                                   |

### Run with Docker

```bash
docker run -d \
  --name trivy-reports \
  -p 127.0.0.1:8000:8000 \
  -v "$(pwd)/instance:/app/instance" \
  -v "$(pwd)/.env:/app/.env:ro" \
  ghcr.io/kbechler/trivy-reports:latest
```

Pinned versions are tagged without the `v` prefix (e.g. pushing git tag `v0.0.1` publishes
`ghcr.io/kbechler/trivy-reports:0.0.1`), matching the convention of most public Docker images.

### Run locally

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # then edit it
gunicorn --workers 4 --bind 127.0.0.1:8000 wsgi:app
```

## Usage

### Uploading a report from CI

```bash
# container image scan
trivy image --format json --output report.json myapp:latest

curl -X POST https://your-host/v1/upload \
  -H "X-Access-Token: $UPLOAD_TOKEN" \
  -H "X-Project: myapp" \
  -H "X-Commit: $(git rev-parse --short HEAD)" \
  -H "X-Tag: v1.2.3" \
  -H "Content-Type: application/json" \
  --data-binary @report.json
```

```bash
# filesystem/repo scan
trivy fs --format json --output report.json .
```

`X-Project` is required; `X-Commit` and `X-Tag` are optional metadata attached to the stored
report. Trivy's JSON `SchemaVersion` must be `2`, and `ArtifactType` must be `filesystem` or
`container_image` — anything else is rejected with `400`.

### Browsing reports

Open `/ui` (Basic Auth, user `admin`) to see two tables — filesystem scans and image scans —
filterable by project, each linking to a per-report detail page with full vulnerability,
misconfiguration, and secret listings.

### Health check

`GET /health` returns a plain `200 OK` and is unauthenticated — used by the Docker
`HEALTHCHECK` and suitable for a load balancer probe.

## Known limitations

This is a deliberately small, single-purpose project — a few things are simplified on purpose:

- No database migrations (Alembic); the schema is created via `db.create_all()` on startup.
  Fine for SQLite/demo use, not for evolving a production schema.
- No automated test suite yet.
- No rate limiting on the login/token checks — acceptable behind a private reverse proxy or VPN,
  not recommended for public exposure as-is.

## Roadmap

Not implemented yet, but planned next:

- **Multi-user accounts with roles** — replace the single `admin` / `ADMIN_PASSWORD` Basic Auth
  user with a proper user table supporting several accounts in two roles: `user` (read-only,
  today's behavior) and `admin` (read-only plus deleting reports).
- **Delete reports** — admins will be able to delete a stored report, cascading to its results,
  vulnerabilities, misconfigurations, and secret findings.
- **Dark theme** — a CSS `prefers-color-scheme`-based dark mode for the UI.

## License

Distributed under the [MIT License](LICENSE).
