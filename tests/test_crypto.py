"""加密/解密核心邏輯測試"""

import pytest
from src.crypto import (
    encrypt_id,
    decrypt_id,
    derive_key,
    _feistel_encrypt,
    _feistel_decrypt,
    _num_to_format,
    _format_to_num,
)


# 預先衍生金鑰以加速測試
KEY_A = derive_key("test_password")
KEY_B = derive_key("password2")


class TestFeistelRoundtrip:
    """Feistel 網絡加解密一致性測試"""

    def test_roundtrip_basic(self):
        for n in [0, 1, 12345678, 99999999, 50000000]:
            encrypted = _feistel_encrypt(n, KEY_A)
            decrypted = _feistel_decrypt(encrypted, KEY_A)
            assert decrypted == n

    def test_different_passwords_produce_different_results(self):
        n = 12345678
        assert _feistel_encrypt(n, KEY_A) != _feistel_encrypt(n, KEY_B)

    def test_deterministic(self):
        n = 12345678
        assert _feistel_encrypt(n, KEY_A) == _feistel_encrypt(n, KEY_A)

    def test_output_in_range(self):
        for n in [0, 99999999, 55555555]:
            encrypted = _feistel_encrypt(n, KEY_A)
            assert 0 <= encrypted <= 99999999

    def test_no_collision(self):
        """測試不同輸入產生不同輸出（一對一映射）"""
        outputs = set()
        for n in range(0, 10000, 7):
            encrypted = _feistel_encrypt(n, KEY_A)
            assert encrypted not in outputs, f"碰撞! n={n}"
            outputs.add(encrypted)


class TestFormatConversion:
    """數字與 4英文+6數字 格式互轉測試"""

    def test_roundtrip(self):
        for m in [0, 1, 999999, 1000000, 50000000, 99999999]:
            formatted = _num_to_format(m)
            restored = _format_to_num(formatted)
            assert restored == m

    def test_format_structure(self):
        formatted = _num_to_format(1500000)
        assert len(formatted) == 10
        assert formatted[:4].isalpha()
        assert formatted[4:].isdigit()

    def test_zero(self):
        assert _num_to_format(0) == "AAAA000000"


class TestEncryptDecryptId:
    """公開 API 加解密測試"""

    def test_roundtrip(self):
        original = "12345678"
        encrypted = encrypt_id(original, KEY_A)
        decrypted = decrypt_id(encrypted, KEY_A)
        assert decrypted == original

    def test_wrong_password_fails(self):
        encrypted = encrypt_id("12345678", KEY_A)
        decrypted = decrypt_id(encrypted, KEY_B)
        assert decrypted != "12345678"

    def test_output_format(self):
        encrypted = encrypt_id("12345678", KEY_A)
        assert len(encrypted) == 10
        assert encrypted[:4].isalpha()
        assert encrypted[4:].isdigit()

    def test_various_inputs(self):
        for input_id in ["00000000", "12345678", "99999999", "00000001"]:
            encrypted = encrypt_id(input_id, KEY_A)
            decrypted = decrypt_id(encrypted, KEY_A)
            assert decrypted == input_id

    def test_invalid_input_length(self):
        with pytest.raises(ValueError):
            encrypt_id("1234567", KEY_A)

    def test_invalid_input_not_digits(self):
        with pytest.raises(ValueError):
            encrypt_id("1234567a", KEY_A)

    def test_all_same_key_different_inputs(self):
        """同一金鑰，不同輸入應產生不同加密結果"""
        results = set()
        for i in range(100):
            encrypted = encrypt_id(str(i).zfill(8), KEY_A)
            assert encrypted not in results
            results.add(encrypted)
