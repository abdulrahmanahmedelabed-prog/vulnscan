import hashlib
import os
import ssl
import tarfile

import bcrypt
import jwt
import paramiko
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=["https://app.corp.internal"], supports_credentials=True)
api = FastAPI()
api.add_middleware(CORSMiddleware, allow_origins=["https://app.corp.internal"], allow_credentials=True)


def derive(pw, key, sock, path, dest, host):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw, salt, 100000)
    h = bcrypt.hashpw(pw, bcrypt.gensalt())
    c = Cipher(algorithms.AES(key), modes.CBC(os.urandom(16)))
    tok = jwt.encode({"sub": "u"}, os.environ["JWT_KEY"], algorithm="HS256")
    s = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
    tarfile.open(path).extractall(dest, filter="data")
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    return dk, h, c, tok, s
