"""
Environment variables

DEVICE_BACKUP_MASTER_KEY_B64 (required)

Used by: encrypt_backup_gz_to_enc(), decrypt_backup_enc_to_bytes(), decrypt_backup_enc_to_gz()

Purpose: The master secret (high-entropy) used to derive per-file AES keys.

Format: Base64 of exactly 32 bytes (AES-256 key material).

Example generation:

python -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"


DEVICE_BACKUP_KDF_PEPPER (optional but recommended)

Used by: _derive_aes_key()

Purpose: Extra secret “pepper” mixed into HKDF info so that even if someone knows the filename (IP+timestamp),
they still cannot reproduce the derived key without the pepper + master key.

Format: Any string (kept secret).



encrypt_backup_gz_to_enc(...)
input_gz_path (str | Path): path to the .gz file you’re encrypting.
output_enc_path (optional str | Path): where to write the .enc file. Default replaces suffix: .gz → .enc.
allowed_input_extensions (Sequence[str]): allowlist for file types you permit encrypting (default (".gz",)).
master_key_env_var (str): env var name to load the master key from (default "DEVICE_BACKUP_MASTER_KEY_B64").
remove_original_on_success (bool): if True, deletes original .gz after successful encrypt+verify.
verify_after_encrypt (bool): if True, decrypts the .enc and checks it “looks like gzip” before deleting original.

decrypt_backup_enc_to_bytes(...)
enc_path (str | Path): path to .enc file.
master_key_env_var (str): env var name for the master key.
decrypt_backup_enc_to_gz(...)
enc_path (str | Path): path to .enc file.
output_gz_path (optional str | Path): where to write decrypted .gz. Default replaces .enc → .gz.
master_key_env_var (str)
remove_enc_on_success (bool): delete the .enc file after successful decrypt+write.

read_gz_text_file(...)
gz_path (str | Path): path to .gz file.
encoding (str): decode encoding (default "utf-8").
errors (str): decode error mode (default "replace").
max_bytes (optional int): if set, reads only up to N decompressed bytes.


Derived / internal variables (created at runtime)
In key derivation

salt (bytes, length 16): random per-file salt created by os.urandom(16).

nonce (bytes, length 12): random AES-GCM nonce created by os.urandom(12).

target_ip (str): extracted from the filename.

timestamp_str (str): extracted from filename and normalized to YYYY-MM-DD HH:MM:SS.

key (bytes, length 32): derived AES-256 key output from HKDF.

aad (bytes): “additional authenticated data” set to ip=<ip>|ts=<timestamp>.
This is not encrypted, but it is integrity-protected (tampering breaks decryption).


On-disk encrypted file structure (what gets stored inside .enc)

The .enc file contains:
MAGIC = b"NTBK1" (identifies the format)
VER = b"\x01" (format version)
IP_LEN (1 byte)
TS_LEN (1 byte)
IP (IP_LEN bytes)
TS (TS_LEN bytes)
SALT (16 bytes)
NONCE (12 bytes)
CIPHERTEXT (AES-GCM encrypted bytes, includes auth tag)

This means decryption does not require the filename to be preserved exactly,
because IP/timestamp are embedded in the file header
(the filename is still used during encryption to build the context initially).

"""

from __future__ import annotations

import base64
import gzip
import os
import re
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, Optional, Sequence, Tuple, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# Matches: <ip>_YYYY_MM_DD_HH_MM_SS   (no extension)
_BACKUP_NAME_RX = re.compile(
    r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})_"
    r"(?P<Y>\d{4})_(?P<m>\d{2})_(?P<d>\d{2})_"
    r"(?P<H>\d{2})_(?P<M>\d{2})_(?P<S>\d{2})$"
)


def _normalize_exts(exts: Sequence[str]) -> set[str]:
    out: set[str] = set()
    for e in exts or []:
        e = str(e).strip().lower()
        if not e:
            continue
        if not e.startswith("."):
            e = "." + e
        out.add(e)
    return out


def _load_master_key_bytes(env_var: str = "DEVICE_BACKUP_MASTER_KEY_B64") -> Tuple[Optional[bytes], Optional[Dict[str, Any]]]:
    """
    Notes / How to run:
      - Put a *random* 32-byte master key in Vault/env (base64-encoded):
          python -c "import os,base64; print(base64.b64encode(os.urandom(32)).decode())"
      - Export it as DEVICE_BACKUP_MASTER_KEY_B64
    """
    b64 = (os.getenv(env_var) or "").strip()
    if not b64:
        return None, {"error": "backup_master_key_missing", "env_var": env_var}

    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception as exc:
        return None, {"error": "backup_master_key_invalid_base64", "env_var": env_var, "detail": str(exc)}

    if len(raw) != 32:
        return None, {"error": "backup_master_key_wrong_length", "env_var": env_var, "expected_len": 32, "actual_len": len(raw)}

    return raw, None


def _parse_ip_and_timestamp_from_filename(path: Path) -> Tuple[Optional[str], Optional[str], Optional[Dict[str, Any]]]:
    """
    File format:
      10.0.0.101_2026_01_27_19_53_50.gz

    Returns:
      (ip, timestamp_str, error)

    timestamp_str is canonicalized to:
      'YYYY-MM-DD HH:MM:SS'
    """
    stem = path.stem  # strips only the last suffix (".gz" -> stem is "10.0.0.101_2026_01_27_19_53_50")
    m = _BACKUP_NAME_RX.match(stem)
    if not m:
        return None, None, {"error": "backup_filename_parse_failed", "filename": path.name, "stem": stem}

    ip = m.group("ip")
    ts = f"{m.group('Y')}-{m.group('m')}-{m.group('d')} {m.group('H')}:{m.group('M')}:{m.group('S')}"
    return ip, ts, None


def _derive_aes_key(
    *,
    master_key: bytes,
    salt: bytes,
    target_ip: str,
    timestamp_str: str,
    pepper_env_var: str = "DEVICE_BACKUP_KDF_PEPPER",
) -> bytes:
    """
    Per-file key derivation:
      key = HKDF(master_key, salt=random, info="network_tools_backup|ip|timestamp|pepper")
    """
    pepper = (os.getenv(pepper_env_var) or "").strip()
    info = f"network_tools_backup|v1|ip={target_ip}|ts={timestamp_str}|pepper={pepper}".encode("utf-8", "replace")

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,          # AES-256
        salt=salt,          # per-file random salt
        info=info,          # binds key to ip+timestamp (+ optional pepper)
    )
    return hkdf.derive(master_key)


# ---------------------------------------------------------------------
# Encryption / Decryption format
# ---------------------------------------------------------------------
#   MAGIC(5) + VER(1) +
#   IP_LEN(1) + TS_LEN(1) + IP + TS +
#   SALT(16) + NONCE(12) + CIPHERTEXT(...)
_MAGIC = b"NTBK1"
_VER = b"\x01"
_SALT_LEN = 16
_NONCE_LEN = 12


def encrypt_backup_gz_to_enc(
    *,
    input_gz_path: Union[str, Path],
    output_enc_path: Optional[Union[str, Path]] = None,
    allowed_input_extensions: Sequence[str] = (".gz",),
    master_key_env_var: str = "DEVICE_BACKUP_MASTER_KEY_B64",
    remove_original_on_success: bool = True,
    verify_after_encrypt: bool = True,
) -> Dict[str, Any]:
    """
    Notes / How to run:
      - Ensure DEVICE_BACKUP_MASTER_KEY_B64 is set (base64 32 bytes).
      - Encrypt:
          encrypt_backup_gz_to_enc(input_gz_path="/backups/.../10.0.0.101_2026-01-27_16-43-59.gz")

    Returns:
      - {"ok": True, "input_path": "...", "output_path": "...", "removed_original": True}
      - {"error": "<code>", ...}
    """
    in_path = Path(str(input_gz_path)).expanduser()
    if not in_path.exists() or not in_path.is_file():
        return {"error": "encrypt_input_not_found", "input_path": str(in_path)}

    allowed = _normalize_exts(allowed_input_extensions)
    if in_path.suffix.lower() not in allowed:
        return {
            "error": "encrypt_extension_not_allowed",
            "input_path": str(in_path),
            "ext": in_path.suffix.lower(),
            "allowed_extensions": sorted(allowed),
        }

    target_ip, timestamp_str, err = _parse_ip_and_timestamp_from_filename(in_path)
    if err:
        return err

    master_key, err = _load_master_key_bytes(master_key_env_var)
    if err:
        return err
    assert master_key is not None

    out_path = Path(str(output_enc_path)).expanduser() if output_enc_path else in_path.with_suffix(".enc")
    if out_path.suffix.lower() != ".enc":
        return {"error": "encrypt_output_must_end_with_enc", "output_path": str(out_path)}

    try:
        plaintext = in_path.read_bytes()

        salt = os.urandom(_SALT_LEN)
        nonce = os.urandom(_NONCE_LEN)

        key = _derive_aes_key(
            master_key=master_key,
            salt=salt,
            target_ip=str(target_ip),
            timestamp_str=str(timestamp_str),
        )

        # AAD binds ciphertext to the same ip/timestamp values (tamper detection)
        aad = f"ip={target_ip}|ts={timestamp_str}".encode("utf-8", "replace")

        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

        ip_b = str(target_ip).encode("utf-8")
        ts_b = str(timestamp_str).encode("utf-8")
        if len(ip_b) > 255 or len(ts_b) > 255:
            return {"error": "encrypt_metadata_too_long", "ip_len": len(ip_b), "ts_len": len(ts_b)}

        header = _MAGIC + _VER + bytes([len(ip_b)]) + bytes([len(ts_b)]) + ip_b + ts_b + salt + nonce
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(header + ciphertext)

        # Verify by decrypting and checking gzip magic
        if verify_after_encrypt:
            ver = decrypt_backup_enc_to_bytes(enc_path=out_path, master_key_env_var=master_key_env_var)
            if ver.get("error"):
                return {"error": "encrypt_verify_failed", "detail": ver}
            data = ver.get("data", b"")
            if not (isinstance(data, (bytes, bytearray)) and data[:2] == b"\x1f\x8b"):
                return {"error": "encrypt_verify_failed_not_gzip", "output_path": str(out_path)}

        if remove_original_on_success:
            in_path.unlink()

        return {"ok": True, "input_path": str(in_path), "output_path": str(out_path), "removed_original": bool(remove_original_on_success)}

    except Exception as exc:
        return {"error": "encrypt_failed", "input_path": str(in_path), "output_path": str(out_path), "detail": str(exc)}


def decrypt_backup_enc_to_bytes(
    *,
    enc_path: Union[str, Path],
    master_key_env_var: str = "DEVICE_BACKUP_MASTER_KEY_B64",
) -> Dict[str, Any]:
    """
    Decrypts .enc and returns raw bytes (expected to be a .gz blob).
    """
    p = Path(str(enc_path)).expanduser()
    if not p.exists() or not p.is_file():
        return {"error": "decrypt_input_not_found", "path": str(p)}

    master_key, err = _load_master_key_bytes(master_key_env_var)
    if err:
        return err
    assert master_key is not None

    try:
        blob = p.read_bytes()
        if len(blob) < 5 + 1 + 1 + 1 + _SALT_LEN + _NONCE_LEN:
            return {"error": "decrypt_file_too_small", "path": str(p)}

        if blob[:5] != _MAGIC or blob[5:6] != _VER:
            return {"error": "decrypt_bad_header", "path": str(p)}

        ip_len = blob[6]
        ts_len = blob[7]
        off = 8
        ip_b = blob[off:off + ip_len]; off += ip_len
        ts_b = blob[off:off + ts_len]; off += ts_len
        salt = blob[off:off + _SALT_LEN]; off += _SALT_LEN
        nonce = blob[off:off + _NONCE_LEN]; off += _NONCE_LEN
        ciphertext = blob[off:]

        target_ip = ip_b.decode("utf-8", "replace")
        timestamp_str = ts_b.decode("utf-8", "replace")

        key = _derive_aes_key(
            master_key=master_key,
            salt=salt,
            target_ip=target_ip,
            timestamp_str=timestamp_str,
        )

        aad = f"ip={target_ip}|ts={timestamp_str}".encode("utf-8", "replace")
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)

        return {"ok": True, "path": str(p), "target_ip": target_ip, "timestamp": timestamp_str, "data": plaintext}

    except Exception as exc:
        return {"error": "decrypt_failed", "path": str(p), "detail": str(exc)}


def decrypt_backup_enc_to_gz(
    *,
    enc_path: Union[str, Path],
    output_gz_path: Optional[Union[str, Path]] = None,
    master_key_env_var: str = "DEVICE_BACKUP_MASTER_KEY_B64",
    remove_enc_on_success: bool = False,
) -> Dict[str, Any]:
    """
    Decrypt .enc back to a .gz file.
    Default output replaces .enc -> .gz
    """
    p = Path(str(enc_path)).expanduser()
    if not p.exists() or not p.is_file():
        return {"error": "decrypt_input_not_found", "path": str(p)}

    out_path = Path(str(output_gz_path)).expanduser() if output_gz_path else p.with_suffix(".gz")
    if out_path.suffix.lower() != ".gz":
        return {"error": "decrypt_output_must_end_with_gz", "output_path": str(out_path)}

    res = decrypt_backup_enc_to_bytes(enc_path=p, master_key_env_var=master_key_env_var)
    if res.get("error"):
        return res

    data = res.get("data", b"")
    if not (isinstance(data, (bytes, bytearray)) and data[:2] == b"\x1f\x8b"):
        return {"error": "decrypt_output_not_gzip", "path": str(p), "detail": "decrypted bytes do not look like gzip"}

    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(data)

        if remove_enc_on_success:
            p.unlink()

        return {"ok": True, "enc_path": str(p), "gz_path": str(out_path), "removed_enc": bool(remove_enc_on_success)}
    except Exception as exc:
        return {"error": "decrypt_write_failed", "enc_path": str(p), "gz_path": str(out_path), "detail": str(exc)}


def read_gz_text_file(
    *,
    gz_path: Union[str, Path],
    encoding: str = "utf-8",
    errors: str = "replace",
    max_bytes: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Open a .gz file and return decompressed text contents.
    """
    p = Path(str(gz_path)).expanduser()
    if not p.exists() or not p.is_file():
        return {"error": "gz_not_found", "path": str(p)}

    try:
        with gzip.open(p, "rb") as f:
            raw = f.read(max_bytes) if max_bytes is not None else f.read()
        return {"ok": True, "path": str(p), "content": raw.decode(encoding, errors=errors), "bytes_read": len(raw)}
    except OSError as exc:
        return {"error": "gz_read_failed", "path": str(p), "detail": str(exc)}


def read_backup_enc_gz_bytes(
    *,
    enc_path: Union[str, Path],
    master_key_env_var: str = "DEVICE_BACKUP_MASTER_KEY_B64",
    max_decompressed_bytes: Optional[int] = None,
) -> Dict[str, Any]:
    """
    One-shot: .enc -> (decrypt to gz-bytes) -> (decompress in memory) -> return raw bytes
    Does NOT write to disk and does NOT delete anything.
    """
    res = decrypt_backup_enc_to_bytes(enc_path=enc_path, master_key_env_var=master_key_env_var)
    if res.get("error"):
        return res

    gz_blob = res.get("data", b"")
    if not (isinstance(gz_blob, (bytes, bytearray)) and gz_blob[:2] == b"\x1f\x8b"):
        return {
            "error": "decrypt_output_not_gzip",
            "path": res.get("path"),
            "detail": "decrypted bytes do not look like gzip",
        }

    try:
        with gzip.GzipFile(fileobj=BytesIO(gz_blob), mode="rb") as gf:
            if max_decompressed_bytes is None:
                raw = gf.read()
            else:
                # read max+1 so we can detect overflow safely
                raw = gf.read(int(max_decompressed_bytes) + 1)
                if len(raw) > int(max_decompressed_bytes):
                    return {
                        "error": "gz_decompressed_too_large",
                        "path": res.get("path"),
                        "max_decompressed_bytes": int(max_decompressed_bytes),
                    }

        return {
            "ok": True,
            "path": res.get("path"),
            "target_ip": res.get("target_ip"),
            "timestamp": res.get("timestamp"),
            "bytes_decompressed": len(raw),
            "data": raw,
        }

    except OSError as exc:
        return {"error": "gz_decompress_failed", "path": res.get("path"), "detail": str(exc)}
    except Exception as exc:
        return {"error": "gz_decompress_unhandled_error", "path": res.get("path"), "detail": str(exc)}


def read_backup_enc_gz_text(
    *,
    enc_path: Union[str, Path],
    master_key_env_var: str = "DEVICE_BACKUP_MASTER_KEY_B64",
    encoding: str = "utf-8",
    errors: str = "replace",
    max_decompressed_bytes: Optional[int] = None,
) -> Dict[str, Any]:
    """
    One-shot: .enc -> (decrypt to gz-bytes) -> (decompress in memory) -> decode -> return text
    Does NOT write to disk and does NOT delete anything.
    """
    res = read_backup_enc_gz_bytes(
        enc_path=enc_path,
        master_key_env_var=master_key_env_var,
        max_decompressed_bytes=max_decompressed_bytes,
    )
    if res.get("error"):
        return res

    raw = res.get("data", b"")
    try:
        text = raw.decode(encoding, errors=errors)
    except Exception as exc:
        return {"error": "decode_failed", "path": res.get("path"), "detail": str(exc)}

    # Don’t return raw bytes AND text unless you want to
    res.pop("data", None)
    res["content"] = text
    return res