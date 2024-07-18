#!/usr/bin/env python3
""" Flask app """

from flask import (
    Flask, jsonify, Response, request,
    make_response, abort, redirect, url_for)
from auth import Auth


AUTH = Auth()
app = Flask(__name__)


# flask View function
@app.route("/", methods=['GET'])
def web_server() -> Response:
    """ App view function with """
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=['POST'])
def register_user() -> Response:
    """ Registers a user"""
    # the form data from the request
    email = request.form.get('email')
    password = request.form.get('password')

    # register the user by Auth.register_user
    # else handle the exception
    try:
        AUTH.register_user(email=email, password=password)
        return jsonify({"email": f"{email}", "message": "user created"})

    except ValueError:
        return jsonify({"message": "email already registered"})


@app.route("/sessions", methods=['POST'])
def login():
    """ Login Route"""
    # Get email and password from request form
    email = request.form.get("email")
    password = request.form.get("password")

    # Check if the credential are correct
    # if its is login
    # and create cookies with session id return it
    if AUTH.valid_login(email=email, password=password):
        # make Response
        resp = make_response(jsonify(
            {"email": f"{email}", "message": "logged in"}))
        session_id = AUTH.create_session(email=email)
        resp.set_cookie("session_id", session_id)
        return resp

    # If the credential do not validate to be true abort 401
    else:
        abort(401)


@app.route("/sessions", methods=["DELETE"])
def logout():
    """ Logs out by destryoing session Id"""
    # Get cookie with session Id key from request
    session_id = request.cookies.get("session_id")

    # find user by session Id
    user = AUTH.get_user_from_session_id(session_id=session_id)

    # if user exists distroy it and redirect it to GET "/"
    if user:
        AUTH.destroy_session(user_id=user.id)
        return redirect(url_for('web_server'))

    # if user doesnt exists abort 403
    else:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
