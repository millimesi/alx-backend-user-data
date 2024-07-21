#!/usr/bin/env python3
"""
Main file
"""
import requests

BASE_URL = "http://localhost:5000"


def register_user(email: str, password: str) -> None:
    """ integration Test"""
    response = requests.post(
        f"{BASE_URL}/users", data={'email': email, 'password': password})
    assert response.status_code == 200, (
        f"Expected status code 200, got {response.status_code}")
    assert response.json() == {"email": email, "message": "user created"}, (
        f"Unexpected response: {response.json()}")


def log_in_wrong_password(email: str, password: str) -> None:
    """ integration Test"""
    response = requests.post(
        f"{BASE_URL}/sessions", data={'email': email, 'password': password})
    assert response.status_code == 401, (
        f"Expected status code 401, got {response.status_code}")


def log_in(email: str, password: str) -> str:
    """ integration Test"""
    response = requests.post(
        f"{BASE_URL}/sessions", data={'email': email, 'password': password})
    assert response.status_code == 200, (
        f"Expected status code 200, got {response.status_code}")
    session_id = response.cookies.get("session_id")
    assert session_id is not None, "No session_id in cookies"
    assert response.json() == {"email": email, "message": "logged in"}, (
        f"Unexpected response: {response.json()}")
    return session_id


def profile_unlogged() -> None:
    """ integration Test"""
    response = requests.get(f"{BASE_URL}/profile")
    assert response.status_code == 403, (
        f"Expected status code 403, got {response.status_code}")


def profile_logged(session_id: str) -> None:
    """ integration Test"""
    cookies = {'session_id': session_id}
    response = requests.get(
        f"{BASE_URL}/profile", cookies=cookies)
    assert response.status_code == 200, (
        f"Expected status code 200, got {response.status_code}")
    assert "email" in response.json(), (
        f"Unexpected response: {response.json()}")


def log_out(session_id: str) -> None:
    """ integration Test"""
    cookies = {'session_id': session_id}
    response = requests.delete(
        f"{BASE_URL}/sessions", cookies=cookies)
    assert response.status_code == 200, (
        f"Expected status code 200, got {response.status_code}")


def reset_password_token(email: str) -> str:
    """ integration Test"""
    response = requests.post(
        f"{BASE_URL}/reset_password", data={'email': email})
    assert response.status_code == 200, (
        f"Expected status code 200, got {response.status_code}")
    reset_token = response.json().get("reset_token")
    assert reset_token is not None, "No reset_token in response"
    return reset_token


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """ integration Test"""
    response = requests.put(f"{BASE_URL}/reset_password", data={
        'email': email,
        'reset_token': reset_token,
        'new_password': new_password
    })
    assert response.status_code == 200, (
        f"Expected status code 200, got {response.status_code}")
    assert (response.json() == (
        {"email": email, "message": "Password updated"}), (
        f"Unexpected response: {response.json()}"))


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
