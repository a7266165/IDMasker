"""
IDMasker 加密/解密核心模組

使用 Format-Preserving Encryption (FPE) 概念，以 Feistel 網絡在有限空間內做一對一映射。

病歷號（8 碼數字）：只加密前 4 碼，末 4 碼保留原文。
    輸出 8 英文字母（大小寫混合）+ 原始末 4 碼數字，共 12 碼。
身份證號（10 碼）：只加密前 6 碼，末 4 碼保留原文。
    輸出 10 英文字母（大小寫混合）+ 原始末 4 碼數字，共 14 碼。
"""

import hmac
import hashlib
import re
import struct

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Hash import HMAC as CRYPTO_HMAC

FIXED_SALT = b"IDMasker_v1_salt"
PBKDF2_ITERATIONS = 100_000
KEY_LENGTH = 32  # 256 bits

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
ALPHABET_SIZE = len(ALPHABET)  # 52
ALPHANUM = ALPHABET + "0123456789"
ALPHANUM_SIZE = len(ALPHANUM)  # 62

# --- 病歷號（前 4 碼）---
FEISTEL_ROUNDS = 8
MODULUS = 100  # sqrt(10^4), 每半邊的大小

# --- 身份證號（前 6 碼）---
NID_LEN = 10
NID_HEAD_LEN = 6  # 加密前 6 碼
NID_LETTERS = 10  # 加密成 10 個英文字母（病歷號是 8 個，可由長度區分群組）
NID_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9]\d{8}$")
NID_ROUNDS = 10
NID_HALF = ALPHABET_SIZE ** (NID_LETTERS // 2)  # 52^5 = 380,204,032，每半邊的大小
NID_SPACE = NID_HALF * NID_HALF  # 52^10 ≈ 1.4e17，10 個字母的輸出空間
NID_DOMAIN = ALPHABET_SIZE * ALPHANUM_SIZE * 10**4  # 52*62*10^4 ≈ 3.2e7，合法前 6 碼總數


def derive_key(password: str) -> bytes:
    """從密碼衍生 256-bit 金鑰"""
    return PBKDF2(
        password.encode("utf-8"),
        FIXED_SALT,
        dkLen=KEY_LENGTH,
        count=PBKDF2_ITERATIONS,
        prf=lambda p, s: CRYPTO_HMAC.new(p, s, SHA256).digest(),
    )


# ======================================================================
# 病歷號：前 4 碼 -> 8 英文字母，末 4 碼原文
# ======================================================================

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
    加密 8 碼病歷號

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
    解密還原 8 碼病歷號

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


# ======================================================================
# 身份證號：前 6 碼 -> 10 英文字母，末 4 碼原文
# ======================================================================

def _nid_head_to_int(head: str) -> int:
    """前 6 碼（1 英文 + 1 英數 + 4 數字）轉成混合進位整數，範圍 [0, NID_DOMAIN)"""
    c0 = ALPHABET.index(head[0])
    c1 = ALPHANUM.index(head[1])
    return (c0 * ALPHANUM_SIZE + c1) * 10**4 + int(head[2:6])


def _int_to_nid_head(n: int) -> str:
    """_nid_head_to_int 的逆運算"""
    n, digits = divmod(n, 10**4)
    c0, c1 = divmod(n, ALPHANUM_SIZE)
    return ALPHABET[c0] + ALPHANUM[c1] + str(digits).zfill(4)


def _int_to_letters(m: int, length: int) -> str:
    """整數以 52 進位編成固定長度的英文字母（高位在前）"""
    out = []
    for _ in range(length):
        m, r = divmod(m, ALPHABET_SIZE)
        out.append(ALPHABET[r])
    return "".join(reversed(out))


def _letters_to_int(s: str) -> int:
    """_int_to_letters 的逆運算"""
    m = 0
    for ch in s:
        m = m * ALPHABET_SIZE + ALPHABET.index(ch)
    return m


def _nid_round(key: bytes, round_num: int, value: int) -> int:
    """身份證號用 Feistel 輪函數：HMAC-SHA256，加域標籤與病歷號區隔"""
    data = b"nid:" + struct.pack(">II", round_num, value)
    h = hmac.new(key, data, hashlib.sha256).digest()
    return int.from_bytes(h[:8], "big") % NID_HALF


def _nid_feistel_encrypt(n: int, key: bytes) -> int:
    """52^10 空間內的一對一映射（左右各 52^5）"""
    L, R = divmod(n, NID_HALF)
    for i in range(NID_ROUNDS):
        L, R = R, (L + _nid_round(key, i, R)) % NID_HALF
    return L * NID_HALF + R


def _nid_feistel_decrypt(n: int, key: bytes) -> int:
    L, R = divmod(n, NID_HALF)
    for i in range(NID_ROUNDS - 1, -1, -1):
        L, R = (R - _nid_round(key, i, L)) % NID_HALF, L
    return L * NID_HALF + R


def encrypt_national_id(national_id: str, key: bytes) -> str:
    """
    加密 10 碼身份證號

    只加密前 6 碼，末 4 碼保留原文。
    前 6 碼先編成整數，在 52^10 空間做 Feistel 後以 52 進位編成 10 個英文字母，
    每個字母位置都有完整 52 種變化，可直接逆運算還原，不需窮舉。

    Args:
        national_id: 10 碼（1 英文 + 1 英數 + 8 數字，如 "A123456789"）
        key: 由 derive_key() 衍生的金鑰

    Returns:
        10 英文字母 + 原始末 4 碼數字（如 "qWeRtYuIoP6789"）
    """
    if not NID_PATTERN.match(national_id):
        raise ValueError("身份證號格式不符：需 1 英文 + 1 英數 + 8 數字，共 10 碼")

    m = _nid_feistel_encrypt(_nid_head_to_int(national_id[:NID_HEAD_LEN]), key)
    return _int_to_letters(m, NID_LETTERS) + national_id[NID_HEAD_LEN:]


def decrypt_national_id(encoded: str, key: bytes) -> str:
    """
    解密還原 10 碼身份證號

    密碼錯誤時，逆運算結果落在合法範圍外的機率約 1 - 2e-10，會拋出 ValueError。

    Args:
        encoded: 10 英文字母 + 4 數字（如 "qWeRtYuIoP6789"）
        key: 由 derive_key() 衍生的金鑰

    Returns:
        原始 10 碼身份證號
    """
    head, tail = encoded[:NID_LETTERS], encoded[NID_LETTERS:]
    if (
        len(encoded) != NID_LETTERS + (NID_LEN - NID_HEAD_LEN)
        or not all(ch in ALPHABET for ch in head)
        or not tail.isdigit()
    ):
        raise ValueError("加密字串格式不符：需 10 英文 + 4 數字，共 14 碼")

    n = _nid_feistel_decrypt(_letters_to_int(head), key)
    if n >= NID_DOMAIN:
        raise ValueError("解密失敗：密碼錯誤或字串損毀")

    return _int_to_nid_head(n) + tail
