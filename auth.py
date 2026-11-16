# auth.py
import hmac
from functools import wraps
from flask import request, jsonify, Response, g, abort
from models.users import User


def require_role(role):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.current_user.role != role:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


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
            user = User.query.filter_by(username=auth.username).first() if auth else None
            if not user or not user.check_password(auth.password):
                return Response(
                    'Authentication required', 401,
                    {'WWW-Authenticate': 'Basic realm="Login Required"'}
                )
            g.current_user = user

        return None
