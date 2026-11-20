# api/v1/__init__.py
from flask import Blueprint
from .routes import register_routes

v1 = Blueprint("v1", __name__)

register_routes(v1)
