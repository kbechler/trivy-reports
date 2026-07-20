# auth.py
import hmac
from flask import request, jsonify, Response, current_app


def register_auth_check(app):

    @app.before_request
    def check_auth():
        if request.path.startswith('/v1'):  # Only protect API routes
            token = request.headers.get('X-Access-Token')
            if not token:
                return jsonify({'error': 'Unauthorized', 'message': 'Auth token not found'}), 401
            if not hmac.compare_digest(token.encode(), app.config['UPLOAD_TOKEN'].encode()):
                return jsonify({'error': 'Unauthorized', 'message': 'Wrong token'}), 401

        if request.path.startswith('/ui'):  # Only protect UI routes
            auth = request.authorization
            if (not auth or auth.username != 'admin'
                    or not hmac.compare_digest(auth.password.encode(), current_app.config['ADMIN_PASSWORD'].encode())):
                return Response(
                    'Authentication required', 401,
                    {'WWW-Authenticate': 'Basic realm="Login Required"'}
                )

        return None
