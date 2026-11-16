# api/ui/routes.py
import csv
import io

from flask import render_template, request, Response, redirect, url_for
from weasyprint import HTML
from werkzeug.utils import secure_filename

from models.reports import ScanReport
from extensions import db
from auth import require_role

DEFAULT_PER_PAGE = 20
ALLOWED_PER_PAGE = [20, 50, 100]
SEVERITY_ORDER = {'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4, 'UNKNOWN': 5}


def _sort_findings_by_severity(report):
    for result in report.results:
        result.vulnerabilities.sort(key=lambda v: SEVERITY_ORDER.get(v.severity, 99))
        result.misconfigurations.sort(key=lambda v: SEVERITY_ORDER.get(v.severity, 99))
        result.secrets.sort(key=lambda v: SEVERITY_ORDER.get(v.severity, 99))


def _report_filename(report, ext):
    project = secure_filename(report.project) if report.project else "report"
    return f"{project}_{report.id}.{ext}"


def register_routes(bp):

    @bp.route('/')
    def splash():
        project_names = db.session.query(ScanReport.project).distinct().all()
        project_names = [p[0] for p in project_names if p[0]]  # flatten and remove None
        selected_project = request.args.get("project")
        vuln_page = request.args.get("vuln_page", 1, type=int)
        image_page = request.args.get("image_page", 1, type=int)
        per_page = request.args.get("per_page", DEFAULT_PER_PAGE, type=int)
        if per_page not in ALLOWED_PER_PAGE:
            per_page = DEFAULT_PER_PAGE

        vuln_query = ScanReport.query.filter_by(artifact_type='filesystem')
        image_query = ScanReport.query.filter_by(artifact_type='container_image')
        if selected_project:
            vuln_query = vuln_query.filter_by(project=selected_project)
            image_query = image_query.filter_by(project=selected_project)

        vuln_pagination = vuln_query.order_by(ScanReport.generated_at.desc()).paginate(
            page=vuln_page, per_page=per_page, error_out=False)
        image_pagination = image_query.order_by(ScanReport.generated_at.desc()).paginate(
            page=image_page, per_page=per_page, error_out=False)

        return render_template("select_report.html",
                               vuln_reports=vuln_pagination.items,
                               image_reports=image_pagination.items,
                               vuln_pagination=vuln_pagination,
                               image_pagination=image_pagination,
                               project_names=project_names,
                               selected_project=selected_project,
                               per_page=per_page,
                               allowed_per_page=ALLOWED_PER_PAGE)

    @bp.route('/report/<int:report_id>')
    def show_report(report_id):
        report = ScanReport.query.get_or_404(report_id)
        _sort_findings_by_severity(report)
        return render_template('report_detail.html', report=report)

    @bp.route('/report/<int:report_id>/export.pdf')
    def export_report_pdf(report_id):
        report = ScanReport.query.get_or_404(report_id)
        _sort_findings_by_severity(report)
        html = render_template('report_detail.html', report=report)
        pdf_bytes = HTML(string=html, base_url=request.base_url).write_pdf()
        return Response(pdf_bytes, mimetype='application/pdf', headers={
            'Content-Disposition': f'attachment; filename="{_report_filename(report, "pdf")}"'
        })

    @bp.route('/report/<int:report_id>/delete', methods=['POST'])
    @require_role('admin')
    def delete_report(report_id):
        report = ScanReport.query.get_or_404(report_id)
        db.session.delete(report)
        db.session.commit()
        return redirect(url_for('ui.splash'))

    @bp.route('/report/<int:report_id>/export.csv')
    def export_report_csv(report_id):
        report = ScanReport.query.get_or_404(report_id)
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(['Type', 'Target', 'Severity', 'ID', 'Title', 'Package', 'Installed',
                         'Fixed', 'Message/Resolution', 'File', 'Lines', 'References'])
        for result in report.results:
            for vuln in result.vulnerabilities:
                writer.writerow(['Vulnerability', result.target, vuln.severity, vuln.vuln_id,
                                 vuln.title, vuln.pkg_name, vuln.installed_version,
                                 vuln.fixed_version or '', '', '', '', vuln.references])
            for misconf in result.misconfigurations:
                writer.writerow(['Misconfiguration', result.target, misconf.severity,
                                 misconf.id_code, misconf.title, '', '', '', misconf.message,
                                 '', '', misconf.references])
            for secret in result.secrets:
                writer.writerow(['Secret', result.target, secret.severity, secret.rule_id,
                                 secret.title, '', '', '', '', secret.file_path,
                                 f'{secret.start_line}-{secret.end_line}', ''])
        return Response(buffer.getvalue(), mimetype='text/csv', headers={
            'Content-Disposition': f'attachment; filename="{_report_filename(report, "csv")}"'
        })
