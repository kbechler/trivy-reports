# api/ui/routes.py
from flask import render_template, request
from models.reports import ScanReport
from extensions import db


def register_routes(bp):

    @bp.route('/')
    def splash():

        project_names = db.session.query(ScanReport.project).distinct().all()
        project_names = [p[0] for p in project_names if p[0]]  # flatten and remove None
        selected_project = request.args.get("project")

        if selected_project:
            vuln_reports = ScanReport.query.filter_by(artifact_type='filesystem').filter_by(
                project=selected_project).order_by(ScanReport.generated_at.desc()).all()
            image_reports = ScanReport.query.filter_by(artifact_type='container_image').filter_by(
                project=selected_project).order_by(ScanReport.generated_at.desc()).all()
        else:
            vuln_reports = ScanReport.query.filter_by(artifact_type='filesystem').order_by(ScanReport.generated_at.desc()).all()
            image_reports = ScanReport.query.filter_by(artifact_type='container_image').order_by(ScanReport.generated_at.desc()).all()

        return render_template("select_report.html",
                               vuln_reports=vuln_reports, image_reports=image_reports,
                               project_names=project_names, selected_project=selected_project)

    @bp.route('/report/<int:report_id>')
    def show_report(report_id):
        report = ScanReport.query.get_or_404(report_id)
        severity_order = {'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4, 'UNKNOWN': 5}
        for result in report.results:
            result.vulnerabilities.sort(key=lambda v: severity_order.get(v.severity, 99))
            result.misconfigurations.sort(key=lambda v: severity_order.get(v.severity, 99))
            result.secrets.sort(key=lambda v: severity_order.get(v.severity, 99))
        return render_template('report_detail.html', report=report)
