"""
IDMasker 加密/解密核心模組

使用 Format-Preserving Encryption (FPE) 概念，
基於 Feistel 網絡在 10^8 空間內進行一對一映射。
輸出格式：4 英文字母（大小寫混合）+ 6 數字
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
MODULUS = 10_000  # sqrt(10^8), 每半邊的大小
DIGIT_SPACE = 1_000_000  # 6 位數字的空間

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
    """Feistel 網絡加密：10^8 空間內的一對一映射"""
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


def _num_to_format(m: int) -> str:
    """將整數 (0~99,999,999) 轉換為 4英文+6數字 格式"""
    letter_idx = m // DIGIT_SPACE  # 0 ~ 99
    digit_part = m % DIGIT_SPACE   # 0 ~ 999,999

    # 將 letter_idx 轉為 4 個字母（base-52 編碼）
    letters = []
    n = letter_idx
    for _ in range(4):
        letters.append(ALPHABET[n % ALPHABET_SIZE])
        n //= ALPHABET_SIZE
    letters.reverse()

    return "".join(letters) + str(digit_part).zfill(6)


def _format_to_num(s: str) -> int:
    """將 4英文+6數字 格式還原為整數"""
    letters = s[:4]
    digits = s[4:]

    letter_idx = 0
    for c in letters:
        letter_idx = letter_idx * ALPHABET_SIZE + ALPHABET.index(c)

    return letter_idx * DIGIT_SPACE + int(digits)


def encrypt_id(eight_digits: str, key: bytes) -> str:
    """
    加密 8 碼數字編號

    Args:
        eight_digits: 8 碼純數字字串（如 "12345678"）
        key: 由 derive_key() 衍生的金鑰

    Returns:
        加密後的 4英文+6數字 字串（如 "AbCd123456"）
    """
    if len(eight_digits) != 8 or not eight_digits.isdigit():
        raise ValueError("輸入必須為 8 碼純數字")

    n = int(eight_digits)
    encrypted = _feistel_encrypt(n, key)
    return _num_to_format(encrypted)


def decrypt_id(encoded: str, key: bytes) -> str:
    """
    解密還原 8 碼數字編號

    Args:
        encoded: 加密後的 4英文+6數字 字串（如 "AbCd123456"）
        key: 由 derive_key() 衍生的金鑰

    Returns:
        原始 8 碼純數字字串（如 "12345678"）
    """
    if len(encoded) != 10:
        raise ValueError("加密字串長度必須為 10 碼")

    m = _format_to_num(encoded)
    decrypted = _feistel_decrypt(m, key)
    return str(decrypted).zfill(8)
