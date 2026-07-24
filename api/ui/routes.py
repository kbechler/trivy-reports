# api/ui/routes.py
from flask import render_template, request
from models.reports import ScanReport
from extensions import db

DEFAULT_PER_PAGE = 20
ALLOWED_PER_PAGE = [20, 50, 100]


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
                               vuln_reports=vuln_pagination.items, image_reports=image_pagination.items,
                               vuln_pagination=vuln_pagination, image_pagination=image_pagination,
                               project_names=project_names, selected_project=selected_project,
                               per_page=per_page, allowed_per_page=ALLOWED_PER_PAGE)

    @bp.route('/report/<int:report_id>')
    def show_report(report_id):
        report = ScanReport.query.get_or_404(report_id)
        severity_order = {'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4, 'UNKNOWN': 5}
        for result in report.results:
            result.vulnerabilities.sort(key=lambda v: severity_order.get(v.severity, 99))
            result.misconfigurations.sort(key=lambda v: severity_order.get(v.severity, 99))
            result.secrets.sort(key=lambda v: severity_order.get(v.severity, 99))
        return render_template('report_detail.html', report=report)
