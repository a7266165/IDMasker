"""資料夾掃描與重命名邏輯測試"""

import pytest
from src.crypto import derive_key
from src.folder_scanner import (
    scan_for_encryption,
    scan_for_decryption,
    encrypt_folder_name,
    decrypt_folder_name,
    rename_folders,
)


KEY = derive_key("test_password")


class TestFolderNameTransform:
    """資料夾名稱轉換測試"""

    def test_encrypt_folder_name(self):
        result = encrypt_folder_name("12345678202602060821", KEY)
        assert len(result) == 22
        assert result[:12] == "202602060821"
        assert result[12:16].isalpha()
        assert result[16:].isdigit()

    def test_decrypt_folder_name_roundtrip(self):
        original = "12345678202602060821"
        encrypted = encrypt_folder_name(original, KEY)
        decrypted = decrypt_folder_name(encrypted, KEY)
        assert decrypted == original

    def test_various_folders(self):
        originals = [
            "12345678202602060821",
            "00000001202601150930",
            "99999999202512311259",
        ]
        for original in originals:
            encrypted = encrypt_folder_name(original, KEY)
            decrypted = decrypt_folder_name(encrypted, KEY)
            assert decrypted == original


class TestScanFolders:
    """資料夾掃描測試"""

    @pytest.fixture
    def temp_dir(self, tmp_path):
        (tmp_path / "12345678202602060821").mkdir()
        (tmp_path / "00000001202601150930").mkdir()
        (tmp_path / "not_a_folder").mkdir()
        (tmp_path / "12345").mkdir()
        (tmp_path / "abcdefghijklmnopqrst").mkdir()  # 20碼但非數字
        (tmp_path / "somefile.txt").touch()
        return tmp_path

    def test_scan_for_encryption(self, temp_dir):
        results = scan_for_encryption(str(temp_dir))
        assert len(results) == 2
        assert "12345678202602060821" in results
        assert "00000001202601150930" in results

    def test_scan_for_decryption(self, temp_dir):
        (temp_dir / "202602060821AbCd123456").mkdir()
        (temp_dir / "202601150930XyZw000001").mkdir()
        results = scan_for_decryption(str(temp_dir))
        assert len(results) == 2

    def test_scan_nonexistent_dir(self):
        with pytest.raises(FileNotFoundError):
            scan_for_encryption("/nonexistent/path")


class TestRenameFolders:
    """批次重命名測試"""

    def test_encrypt_rename(self, tmp_path):
        folder_name = "12345678202602060821"
        (tmp_path / folder_name).mkdir()

        results = rename_folders(
            str(tmp_path), [folder_name], "password", "encrypt"
        )

        assert len(results) == 1
        assert results[0]["success"] is True
        assert not (tmp_path / folder_name).exists()
        assert (tmp_path / results[0]["new_name"]).exists()

    def test_decrypt_rename(self, tmp_path):
        original = "12345678202602060821"
        password = "roundtrip"
        (tmp_path / original).mkdir()
        enc_results = rename_folders(str(tmp_path), [original], password, "encrypt")
        encrypted_name = enc_results[0]["new_name"]

        dec_results = rename_folders(
            str(tmp_path), [encrypted_name], password, "decrypt"
        )

        assert dec_results[0]["success"] is True
        assert dec_results[0]["new_name"] == original
        assert (tmp_path / original).exists()

    def test_target_already_exists(self, tmp_path):
        folder_name = "12345678202602060821"
        (tmp_path / folder_name).mkdir()

        target_name = encrypt_folder_name(folder_name, derive_key("password"))
        (tmp_path / target_name).mkdir()

        results = rename_folders(
            str(tmp_path), [folder_name], "password", "encrypt"
        )

        assert results[0]["success"] is False
        assert "已存在" in results[0]["error"]
