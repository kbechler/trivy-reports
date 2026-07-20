# api/ui/__init__.py
from flask import Blueprint
from .routes import register_routes

ui = Blueprint('ui', __name__)

register_routes(ui)
