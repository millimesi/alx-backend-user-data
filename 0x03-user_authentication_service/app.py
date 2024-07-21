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

    # if session id is not given in the cookies abort with 403
    if not session_id:
        abort(403)

    # find user by session Id
    user = AUTH.get_user_from_session_id(session_id=session_id)

    # if user exists distroy it and redirect it to GET "/"
    if user:
        AUTH.destroy_session(user_id=user.id)
        return redirect(url_for('web_server'))

    # if user doesnt exists abort 403
    else:
        abort(403)


@app.route("/profile", methods=["GET"])
def profile():
    """ returns the profile of The user"""
    # Get the session id from the cookie
    session_id = request.cookies.get("session_id")

    # if not session Id abort with 403
    if not session_id:
        abort(403)

    # try to get the user by the session id
    try:
        user = AUTH.get_user_from_session_id(session_id=session_id)
        return jsonify({"email": f"{user.email}"}), 200

    # if exception raised by get_user_from_session_id
    # Abort with not found 404
    except Exception:
        abort(403)


@app.route("/reset_password", methods=["POST"])
def get_reset_password_token():
    """ Generate reset_token and responds it"""
    # Get the email from the request
    email = request.form.get("email")

    # if the email is not given abort with 403
    if not email:
        abort(403)

    # try to get password reset token
    try:
        reset_token = AUTH.get_reset_password_token(email=email)

        # retun the rest_token
        return jsonify(
            {"email": f"{email}", "reset_token": f"{reset_token}"}), 200

    # if exception is raised by not email abort with 403
    except Exception:
        abort(403)


@app.route("/reset_password", methods=["PUT"])
def update_password():
    """ Reset the password with form data of
    email, rest_token, and new password"""
    # Get email, reset_token, and password
    email = request.form.get("email")
    reset_token = request.form.get("reset_token")
    new_password = request.form.get("new_password")

    # if one of the above datas doesnt exists abort with 403
    if (email is None or reset_token is None or
            new_password is None):
        abort(403)

    # try to update the password with update password method
    try:
        AUTH.update_password(
            reset_token=reset_token, password=new_password)

        # return update statuse info
        return jsonify(
            {"email": f"{email}", "message": "Password updated"}), 200

    # if update_password raises Value Error
    # Because NotFound Exception abort with 403
    except Exception:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
