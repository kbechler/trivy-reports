# models/reports.py
from datetime import datetime, timezone
from extensions import db

class ScanReport(db.Model): # pylint: disable=too-few-public-methods
    id = db.Column(db.Integer, primary_key=True)
    schema_version = db.Column(db.String(20))
    generated_at = db.Column(db.DateTime)
    uploaded_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    project = db.Column(db.String(100))
    commit = db.Column(db.String(100))
    tag = db.Column(db.String(100))
    results = db.relationship('ScanResult', backref='report', cascade='all, delete-orphan')
    artifact_name = db.Column(db.String)
    artifact_type = db.Column(db.String)
    image_id = db.Column(db.String)
    os = db.Column(db.String)
    size = db.Column(db.Integer)

class ScanResult(db.Model): # pylint: disable=too-few-public-methods
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('scan_report.id'))
    target = db.Column(db.String(255))
    class_ = db.Column(db.String(50))
    type = db.Column(db.String(50))
    vulnerabilities = db.relationship('Vulnerability', backref='result', cascade='all, delete-orphan')
    misconfigurations = db.relationship('Misconfiguration', backref='result', cascade='all, delete-orphan')
    secrets = db.relationship('SecretFinding', backref='result', cascade='all, delete-orphan')

class Vulnerability(db.Model): # pylint: disable=too-few-public-methods
    id = db.Column(db.Integer, primary_key=True)
    result_id = db.Column(db.Integer, db.ForeignKey('scan_result.id'))
    vuln_id = db.Column(db.String(50))
    pkg_name = db.Column(db.String(100))
    installed_version = db.Column(db.String(50))
    fixed_version = db.Column(db.String(50))
    severity = db.Column(db.String(20))
    title = db.Column(db.Text)
    references = db.Column(db.Text)  # store as comma-separated or JSON string

class Misconfiguration(db.Model): # pylint: disable=too-few-public-methods
    id = db.Column(db.Integer, primary_key=True)
    result_id = db.Column(db.Integer, db.ForeignKey('scan_result.id'))
    id_code = db.Column(db.String(100))  # e.g. "AVD-XYZ"
    title = db.Column(db.Text)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20))
    message = db.Column(db.Text)
    resolution = db.Column(db.Text)
    references = db.Column(db.Text)

class SecretFinding(db.Model): # pylint: disable=too-few-public-methods
    id = db.Column(db.Integer, primary_key=True)
    result_id = db.Column(db.Integer, db.ForeignKey('scan_result.id'))
    rule_id = db.Column(db.String(100))  # e.g. "aws-secret-access-key"
    category = db.Column(db.String(50))
    severity = db.Column(db.String(20))
    title = db.Column(db.Text)
    match = db.Column(db.Text)
    file_path = db.Column(db.String(255))
    start_line = db.Column(db.Integer)
    end_line = db.Column(db.Integer)
