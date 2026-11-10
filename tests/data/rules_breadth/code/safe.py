import ssl

import aiohttp
import redis
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

JWT_OPTIONS = {"verify_signature": True}

ctx = ssl.create_default_context()
ctx.check_hostname = True
ctx.minimum_version = ssl.TLSVersion.TLSv1_2
use_ssl = False
cache = redis.Redis(host="cache", ssl=False)


async def fetch(url, pinned):
    async with aiohttp.ClientSession() as s:
        return await s.get(url, ssl=pinned)


def encrypt(key, iv, data):
    return Cipher(algorithms.AES(key), modes.GCM(iv))


CORS_SETTINGS = {"origins": ["https://app.corp.internal"], "supports_credentials": True}

# Comments that name a dangerous setting are not code:
# never set ctx.check_hostname = False or pass ssl=False to aiohttp.ClientSession().get(url)
