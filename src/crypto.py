"""
IDMasker 加密/解密核心模組

使用 Format-Preserving Encryption (FPE) 概念，
基於 Feistel 網絡在 10^4 空間內進行一對一映射。
只加密前 4 碼，末 4 碼保留原文。
輸出格式：8 英文字母（大小寫混合）+ 原始末 4 碼數字
"""

import hmac
import hashlib
import struct

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC as CRYPTO_HMAC

FIXED_SALT = b"IDMasker_v1_salt"
PBKDF2_ITERATIONS = 100_000
KEY_LENGTH = 32  # 256 bits
FEISTEL_ROUNDS = 8
MODULUS = 100  # sqrt(10^4), 每半邊的大小

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
ALPHABET_SIZE = len(ALPHABET)  # 52


def derive_key(password: str) -> bytes:
    """從密碼衍生 256-bit 金鑰"""
    return PBKDF2(
        password.encode("utf-8"),
        FIXED_SALT,
        dkLen=KEY_LENGTH,
        count=PBKDF2_ITERATIONS,
        prf=lambda p, s: CRYPTO_HMAC.new(p, s, SHA256).digest(),
    )


def _feistel_round(key: bytes, round_num: int, value: int) -> int:
    """Feistel 輪函數：使用 HMAC-SHA256"""
    data = struct.pack(">II", round_num, value)
    h = hmac.new(key, data, hashlib.sha256).digest()
    return int.from_bytes(h[:4], "big") % MODULUS


def _feistel_encrypt(n: int, key: bytes) -> int:
    """Feistel 網絡加密：10^4 空間內的一對一映射"""
    L = n // MODULUS
    R = n % MODULUS

    for i in range(FEISTEL_ROUNDS):
        f = _feistel_round(key, i, R)
        L, R = R, (L + f) % MODULUS

    return L * MODULUS + R


def _feistel_decrypt(n: int, key: bytes) -> int:
    """Feistel 網絡解密：逆向操作"""
    L = n // MODULUS
    R = n % MODULUS

    for i in range(FEISTEL_ROUNDS - 1, -1, -1):
        f = _feistel_round(key, i, L)
        L, R = (R - f) % MODULUS, L

    return L * MODULUS + R


def _num_to_letters(m: int, key: bytes) -> str:
    """
    將整數 (0~9999) 透過 HMAC 衍生為 8 個英文字母。

    使用 HMAC(key, m) 讓每個字母位置都有完整的 52 種變化，
    避免 base-52 編碼造成的前導 A 問題。
    """
    data = struct.pack(">I", m)
    h = hmac.new(key, b"letters:" + data, hashlib.sha256).digest()
    return "".join(ALPHABET[b % ALPHABET_SIZE] for b in h[:8])


def _letters_to_num(s: str, key: bytes) -> int:
    """
    將 8 個英文字母透過窮舉還原為整數。

    僅需搜尋 0~9999 共 10,000 個值，瞬間完成。
    """
    for m in range(10000):
        if _num_to_letters(m, key) == s:
            return m
    raise ValueError("解密失敗：找不到匹配的字母組合")


def encrypt_id(eight_digits: str, key: bytes) -> str:
    """
    加密 8 碼數字編號

    只加密前 4 碼，末 4 碼保留原文。

    Args:
        eight_digits: 8 碼純數字字串（如 "12345678"）
        key: 由 derive_key() 衍生的金鑰

    Returns:
        加密後的 8英文+4數字 字串（如 "xKpRmNvB5678"）
    """
    if len(eight_digits) != 8 or not eight_digits.isdigit():
        raise ValueError("輸入必須為 8 碼純數字")

    first_four = int(eight_digits[:4])
    last_four = eight_digits[4:]

    encrypted = _feistel_encrypt(first_four, key)
    letters = _num_to_letters(encrypted, key)

    return letters + last_four


def decrypt_id(encoded: str, key: bytes) -> str:
    """
    解密還原 8 碼數字編號

    Args:
        encoded: 加密後的 8英文+4數字 字串（如 "xKpRmNvB5678"）
        key: 由 derive_key() 衍生的金鑰

    Returns:
        原始 8 碼純數字字串（如 "12345678"）
    """
    if len(encoded) != 12:
        raise ValueError("加密字串長度必須為 12 碼")

    letters = encoded[:8]
    last_four = encoded[8:]

    m = _letters_to_num(letters, key)
    decrypted = _feistel_decrypt(m, key)
    first_four = str(decrypted).zfill(4)

    return first_four + last_four
