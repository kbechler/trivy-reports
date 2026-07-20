# api/v1/routes.py
from datetime import datetime
from flask import jsonify, request, abort
from extensions import db
from models.reports import ScanReport, ScanResult, Vulnerability, Misconfiguration, SecretFinding


def register_routes(bp):

    @bp.route('/<path:invalid_path>')
    def catch_all(invalid_path):  # pylint: disable=unused-argument
        abort(404)

    @bp.route('/upload', methods=['POST'])
    def upload():

        # This will automatically return a "400 Bad Request" if
        # the incoming data isn't valid JSON and the "Content-Type"
        # is set to "application/json".
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Invalid or missing JSON'}), 400

        project_name = request.headers.get('X-Project')
        if not project_name:
            return jsonify({'error': 'No project name'}), 400

        required_keys = ['SchemaVersion', 'ArtifactName', 'ArtifactType', 'Results', 'CreatedAt']
        if not all(key in data for key in required_keys):
            return jsonify({'error': 'Unknown JSON structure'}), 400
        if data['SchemaVersion'] != 2:
            return jsonify({'error': 'Unknown JSON structure'}), 400
        if data['ArtifactType'] not in ['filesystem', 'container_image']:
            return jsonify({'error': 'Unknown JSON structure'}), 400

        try:
            generated_at = datetime.fromisoformat(data['CreatedAt'])
        except (TypeError, ValueError):
            return jsonify({'error': 'Invalid CreatedAt timestamp'}), 400

        os_info = data.get('Metadata', {}).get('OS', {})
        os_string = f"{os_info.get('Family', '')} {os_info.get('Name', '')}".strip()
        report = ScanReport(
            schema_version=data.get('SchemaVersion'),
            generated_at=generated_at,
            project=request.headers.get('X-Project'),

            artifact_name=data.get('ArtifactName'),
            artifact_type=data.get('ArtifactType'),
            image_id=data.get('Metadata', {}).get('ImageID'),
            os=os_string,
            size=data.get('Metadata', {}).get('Size'),
            commit = request.headers.get('X-Commit'),
            tag = request.headers.get('X-Tag')
        )
        db.session.add(report)




        for result in data['Results']:
            res = ScanResult(
                target=result.get('Target'),
                class_=result.get('Class'),
                type=result.get('Type'),
                report=report
            )
            db.session.add(res)

            for vuln in result.get('Vulnerabilities') or []:
                v = Vulnerability(
                    vuln_id=vuln.get('VulnerabilityID'),
                    pkg_name=vuln.get('PkgName'),
                    installed_version=vuln.get('InstalledVersion'),
                    fixed_version=vuln.get('FixedVersion'),
                    severity=vuln.get('Severity'),
                    title=vuln.get('Title'),
                    references=', '.join(vuln.get('References', [])),
                    result=res
                )
                db.session.add(v)

            for misconf in result.get('Misconfigurations') or []:
                db.session.add(Misconfiguration(
                    result=res,
                    id_code=misconf.get('ID'),
                    title=misconf.get('Title'),
                    description=misconf.get('Description'),
                    severity=misconf.get('Severity'),
                    message=misconf.get('Message'),
                    resolution=misconf.get('Resolution'),
                    references=', '.join(misconf.get('References', []))
                ))

            for secret in result.get('Secrets') or []:
                db.session.add(SecretFinding(
                    result=res,
                    rule_id=secret.get('RuleID'),
                    category=secret.get('Category'),
                    severity=secret.get('Severity'),
                    title=secret.get('Title'),
                    match=secret.get('Match'),
                    file_path=secret.get('FilePath'),
                    start_line=secret.get('StartLine'),
                    end_line=secret.get('EndLine')
                ))

        db.session.commit()
        return jsonify({'status': 'ok'})
