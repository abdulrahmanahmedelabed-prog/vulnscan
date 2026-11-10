import hashlib
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
# expect-next: vql/cors-credentials-any-origin
CORS(app,
     supports_credentials=True)
api = FastAPI()
# expect-next: vql/cors-credentials-any-origin
api.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_credentials=True)


def derive(pw, key, sock, path, dest):
    # expect-next: vql/kdf-hardcoded-salt
    dk = hashlib.pbkdf2_hmac("sha256", pw, b"fixedsalt", 100000)
    # expect-next: vql/kdf-hardcoded-salt
    h = bcrypt.hashpw(pw, b"$2b$12$abcdefghijklmnopqrstuu")
    # expect-next: vql/cipher-static-iv
    c = Cipher(algorithms.AES(key), modes.CBC(b"0123456789abcdef"))
    # expect-next: vql/jwt-hardcoded-secret
    tok = jwt.encode({"sub": "u"}, "hardcoded", algorithm="HS256")
    # expect-next: vql/ssl-wrap-socket-unverified
    s = ssl.wrap_socket(sock)
    # expect-next: vql/tarfile-extractall-no-filter
    tarfile.open(path).extractall(dest)
    client = paramiko.SSHClient()
    # expect-next: vql/ssh-auto-add-host-key
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    return dk, h, c, tok, s
