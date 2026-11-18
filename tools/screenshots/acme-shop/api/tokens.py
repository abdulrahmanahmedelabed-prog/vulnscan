import hashlib
import random


def reset_token(user_id):
    return hashlib.md5(f"{user_id}{random.random()}".encode()).hexdigest()
