import ssl

import aiohttp
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

JWT_OPTIONS = {
    # expect-next: JWT001
    "verify_signature": False,
}

ctx = ssl.create_default_context()
# expect-next: TLS007
ctx.check_hostname = False
# expect-next: TLS006
ctx.minimum_version = ssl.TLSVersion.TLSv1


async def fetch(url):
    async with aiohttp.ClientSession() as s:
        # expect-next: TLS001
        return await s.get(url, ssl=False)


def encrypt(key, iv, data):
    # expect-next: CRY008
    ecb = Cipher(algorithms.AES(key), modes.ECB())
    # expect-next: CRY009
    legacy = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
    return ecb, legacy


# expect-next: CORS001
CORS_SETTINGS = {"origins": "*", "supports_credentials": True}
