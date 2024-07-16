#!/usr/bin/env python3
"""
Route module for the API
"""
from os import getenv
from api.v1.views import app_views
from flask import Flask, jsonify, abort, request
from flask_cors import (CORS, cross_origin)
import os


app = Flask(__name__)
app.register_blueprint(app_views)
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})
# create auth variable
auth = None

# assignment of auth based on the given authentication
if getenv('AUTH_TYPE'):
    from api.v1.auth.auth import Auth
    auth = Auth()


@app.before_request
def before_requesr_handler():
    '''
    Filters Authntication for each request
    '''
    # if auth is None do nothing
    if auth is None:
        return

    # Check for excluded paths from authentication
    path = request.path
    excluded_paths = [
        '/api/v1/status/', '/api/v1/unauthorized/', '/api/v1/forbidden/']
    auth.require_auth(path, excluded_paths)

    # unauthoriztion abort
    if auth.authorization_header(request) is None:
        abort(401)

    # forbidden abort
    if auth.authorization_header(request) is None:
        abort(403)


@app.errorhandler(404)
def not_found(error) -> str:
    """ Not found handler
    """
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(401)
def unauthorized(error) -> str:
    """ Unauthorized error handler
    """
    return jsonify(error=str("Unauthorized")), 401


@app.errorhandler(403)
def forbidden(error) -> str:
    """ forbidden error handler
    """
    return jsonify(error=str("Forbidden")), 403


if __name__ == "__main__":
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    app.run(host=host, port=port, debug=True)
