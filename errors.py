# errors.py
from flask import jsonify


def register_error_handlers(app):
    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(405)
    @app.errorhandler(415)
    def err(e):
        return jsonify({'code': e.code, 'status': 'err', 'message': e.description}), e.code
