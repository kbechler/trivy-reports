# api/ui/__init__.py
from flask import Blueprint, g
from .routes import register_routes

ui = Blueprint('ui', __name__)

register_routes(ui)


@ui.context_processor
def inject_current_user():
    return {'current_user': g.get('current_user')}
