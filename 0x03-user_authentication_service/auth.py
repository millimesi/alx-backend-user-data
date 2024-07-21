#!/usr/bin/env python3
""" user authentication service """

import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError
from typing import Union
import uuid


def _hash_password(password: str) -> bytes:
    """
    hashes a password with salt
    Args:
        password(str):
    Returns:
        bytes: salted hashed bytes of the password
    """
    # create Salt
    salt = bcrypt.gensalt()

    # Hash the pasword
    _hashed_pwd = bcrypt.hashpw(password.encode('utf-8'), salt)

    return _hashed_pwd


def _generate_uuid() -> str:
    """ retuns function string representation of uuid"""
    return str(uuid.uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """Initializtions of the Authc class"""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """ Registors a user if it doesnt exists
        Args:
            email(str): email of the user
            Password(str): password of the user
        Returns:
            User: User of created object
        """
        # try to find the user with method of
        # if user exists raise a Value error
        try:
            user = self._db.find_user_by(email=email)
            if user:
                raise ValueError(f"User {email} already exists")

        # if NoResultFound Exception raises NotResultFound
        # add it to the database and return it
        except NoResultFound:
            hashed_password = _hash_password(password=password)
            user = self._db.add_user(
                email=email, hashed_password=hashed_password)
            return user

        # find_user_by may raise the InvalidrequestError
        # so I wanted to handle it
        except InvalidRequestError:
            raise InvalidRequestError()

    def valid_login(self, email: str, password: str) -> bool:
        """
        Validate the login password
         Args:
            email(str): email of the user
            Password(str): password of the user
        Returns:
            boolean: True if it matches else False
        """
        # find the user
        try:
            user = self._db.find_user_by(email=email)

            # if user exists match the password
            if user:

                # return the bycrpt check result
                # if it matched True else False
                return bcrypt.checkpw(
                    password.encode('utf-8'),
                    user.hashed_password)

        # in other case return False
        except Exception:
            return False

    def create_session(self, email: str) -> str:
        """
        Create a session id Correspondans to the user
        Args:
             email(str): emails of the user
        Returns:
            str: session uuid of the session
        """
        # try to find the user
        try:
            user = self._db.find_user_by(email=email)
            user_id = user.id

            # if user exists create the session id
            if user:
                session_id = _generate_uuid()

                # update the user in database with session_id
                try:
                    self._db.update_user(
                        user_id=user_id, session_id=session_id)
                    return session_id
                except ValueError:
                    return "Invalid Value"

        # in other case return False
        except Exception:
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """
        finds a user with session_id
        Args:
            session_id: string uuid
        Returns:
            User or None: if the user exist it will be returned or None
        """
        # try to find the user by session Id
        # if it is found return it
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user

        # if error is raised means not found return None
        except Exception:
            return None

    def destroy_session(self, user_id: str) -> None:
        """
        update users session_id to None
        with a given id
        Args:
            user_id(str): user Id
        Returns:
            None:
        """
        self._db.update_user(user_id=user_id, session_id=None)
        return None

    def get_reset_password_token(self, email: str) -> str:
        """ create and return password reset token
        Args:
            email(str): email of the user
        Returns:
            str: string uuid rest token
        """
        # try to find the user with the email
        try:
            user = self._db.find_user_by(email=email)

            # generate rest_token from the uuid
            reset_token = _generate_uuid()

            # update the user rest_token column with
            # the generated token and return the token
            self._db.update_user(user_id=user.id, reset_token=reset_token)
            return reset_token

        # if the use is not found raise vale error
        except Exception:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """ update the password of the user by taking the reset_token
        Args:
            reset_token(str): reset_token given before
            password(str): the new password
        Return:
            None
        """
        # try to find the user using the reset_token
        try:
            user = self._db.find_user_by(reset_token=reset_token)

            # hash the password
            new_hashed_password = _hash_password(password=password)

            # update the reset token with new hashed password
            self._db.update_user(
                user_id=user.id, hashed_password=new_hashed_password)

            return None

        # if the user is not found with rest_token raise value error
        except Exception:
            raise ValueError
