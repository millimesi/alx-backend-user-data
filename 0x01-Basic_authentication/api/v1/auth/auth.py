#!/usr/bin/env python3
"""
Basic Authentication Module
"""
from flask import request
from typing import List, TypeVar


class Auth:
    """Basic Authentication class"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        require_auth

        Args:
            path(str):
            excluded_paths(str):

        Returns:
            bool:
        """
        # Return true if path is none
        if path is None:
            return True

        # Return true if excluded_path is None or empty
        if excluded_paths == [] or excluded_paths is None:
            return True

        # concat '/' if path doesnt have slash at the end
        path = path + '/' if not path.endswith('/') else path

        # Return False if path is in excluded path
        return False if path in excluded_paths else True

    def authorization_header(self, request=None) -> str:
        """
        authorization_header

        Args:
            request:

        Returns:
            str:
        """
        # if Request is none return None
        if request is None:
            return None

        # If request contain header Authoriztion return it else None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):  # type: ignore
        """
        Current_user
        Args:
            request:
        Returns:
            TypeVar('request'):
        """
        return None
