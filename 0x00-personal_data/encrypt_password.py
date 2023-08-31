#!/usr/bin/env python3
"""
File: encrypt_password
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """ Takes in string arg, converts to unicode
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ Checks if hashed and unhashed pswds
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
