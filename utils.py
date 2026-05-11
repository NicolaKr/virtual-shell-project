"""utils.py – shared utilities for the virtual shell project.

Contains:
  - random_password()        — generate a random password string
  - encrypt_codename()       — obfuscate a plain codename for embedding in notebooks
  - decrypt_codename()       — reverse of encrypt_codename
"""

import base64
import random
import string

# XOR key used for codename obfuscation (must match in cli.py)
_KEY = 120


def random_password(length: int = 8) -> str:
    """Return a random alphanumeric password of the given length."""
    return "".join(random.choice(string.ascii_letters + string.digits)
                   for _ in range(length))


def encrypt_codename(plain: str) -> str:
    """Encrypt a plain codename → opaque string safe to embed in a notebook cell.

    Flow:  plain  ──b64encode──▶  bytes  ──XOR──▶  bytes  ──b64encode──▶  str
    The outer b64 makes the result printable / copy-pasteable.
    """
    xored = bytes(b ^ _KEY for b in base64.b64encode(plain.encode()))
    return base64.b64encode(xored).decode()


def decrypt_codename(token: str) -> str:
    """Reverse of encrypt_codename.  Raises ValueError on a bad token."""
    try:
        xored = base64.b64decode(token.encode())
        inner = bytes(b ^ _KEY for b in xored)
        return base64.b64decode(inner).decode()
    except Exception as exc:
        raise ValueError(f"Invalid encrypted codename token: {token!r}") from exc