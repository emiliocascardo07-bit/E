#!/usr/bin/env python3
"""
encrypt_page.py — wrap a dashboard HTML page in a password gate.

Reads an HTML file (the hourly routine's dashboard — a body fragment with inline
styles/scripts), encrypts the WHOLE thing with AES-256-GCM, and writes a small
public "shell" page that contains nothing but a password form and the base64
ciphertext. Nothing readable about the dashboard survives in the output file.

Crypto parameters (must stay in sync with the JS in shell_template.html):
    KDF          PBKDF2-HMAC-SHA256
    iterations   600_000
    salt         16 random bytes (os.urandom), fresh per encryption
    key          32 bytes (AES-256)
    cipher       AES-256-GCM
    IV / nonce   12 random bytes (os.urandom), fresh per encryption
    tag          128 bits, appended to the ciphertext (the `cryptography`
                 AESGCM API and WebCrypto both use ct||tag)
    plaintext    the input file, encoded UTF-8, byte-for-byte

Dependency: `cryptography` (pip install cryptography). The stdlib has PBKDF2
(hashlib.pbkdf2_hmac) but no AES at all, so one wheel is unavoidable.

Usage:
    pip install cryptography
    python3 encrypt_page.py <input.html> <output_index.html> <passphrase>
"""

import base64
import json
import os
import sys

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover - environment guard
    sys.exit(
        "Missing dependency: cryptography\n"
        "Install it first:  pip install cryptography\n"
        "(The Python stdlib ships PBKDF2 but no AES, so this is required.)"
    )

import hashlib

# --- crypto parameters -------------------------------------------------------
PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16
IV_BYTES = 12
KEY_BYTES = 32          # AES-256
TAG_BITS = 128          # GCM auth tag, carried at the end of the ciphertext

TEMPLATE_NAME = "shell_template.html"
PLACEHOLDER = "__PAYLOAD_JSON__"


def derive_key(passphrase: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """PBKDF2-HMAC-SHA256 -> 32-byte AES key. Same construction as WebCrypto."""
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations, dklen=KEY_BYTES)


def encrypt_html(plaintext: bytes, passphrase: str, iterations: int = PBKDF2_ITERATIONS) -> dict:
    """Encrypt `plaintext` and return the JSON payload embedded in the shell."""
    salt = os.urandom(SALT_BYTES)
    iv = os.urandom(IV_BYTES)
    key = derive_key(passphrase, salt, iterations)
    ct = AESGCM(key).encrypt(iv, plaintext, None)  # ciphertext || 16-byte tag
    return {
        "v": 1,
        "kdf": "PBKDF2-SHA256",
        "iterations": iterations,
        "cipher": "AES-256-GCM",
        "tagBits": TAG_BITS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "ct": base64.b64encode(ct).decode("ascii"),
    }


def decrypt_payload(payload: dict, passphrase: str) -> bytes:
    """Inverse of encrypt_html. Raises cryptography.exceptions.InvalidTag on a bad password."""
    salt = base64.b64decode(payload["salt"])
    iv = base64.b64decode(payload["iv"])
    ct = base64.b64decode(payload["ct"])
    key = derive_key(passphrase, salt, int(payload["iterations"]))
    return AESGCM(key).decrypt(iv, ct, None)


def load_template(template_path: str) -> str:
    with open(template_path, "r", encoding="utf-8") as fh:
        template = fh.read()
    if PLACEHOLDER not in template:
        raise SystemExit(f"Template {template_path} has no {PLACEHOLDER} placeholder.")
    return template


def build_shell(payload: dict, template: str) -> str:
    blob = json.dumps(payload, separators=(",", ":"))
    # Defensive: never let a literal "</" close the host <script> element early.
    blob = blob.replace("</", "<\\/")
    return template.replace(PLACEHOLDER, blob)


def extract_payload(shell_html: str) -> dict:
    """Pull the JSON payload back out of a generated shell page (used by tests)."""
    start_tag = '<script id="payload" type="application/json">'
    start = shell_html.index(start_tag) + len(start_tag)
    end = shell_html.index("</script>", start)
    return json.loads(shell_html[start:end].replace("<\\/", "</"))


def main(argv):
    if len(argv) != 4:
        sys.exit("usage: python3 encrypt_page.py <input.html> <output_index.html> <passphrase>")

    in_path, out_path, passphrase = argv[1], argv[2], argv[3]
    if not passphrase:
        sys.exit("Refusing to encrypt with an empty passphrase.")

    with open(in_path, "rb") as fh:
        plaintext = fh.read()

    template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), TEMPLATE_NAME)
    template = load_template(template_path)

    payload = encrypt_html(plaintext, passphrase)
    shell = build_shell(payload, template)

    out_dir = os.path.dirname(os.path.abspath(out_path))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(shell)

    print(
        f"encrypted {in_path} ({len(plaintext):,} bytes) -> {out_path} "
        f"({len(shell.encode('utf-8')):,} bytes)\n"
        f"  AES-256-GCM · PBKDF2-SHA256 x{PBKDF2_ITERATIONS:,} · "
        f"{SALT_BYTES}-byte salt · {IV_BYTES}-byte IV · {TAG_BITS}-bit tag"
    )


if __name__ == "__main__":
    main(sys.argv)
