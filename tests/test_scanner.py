"""資料夾掃描與重命名邏輯測試"""

import pytest
from src.crypto import derive_key
from src.folder_scanner import (
    scan_for_encryption,
    scan_for_decryption,
    encrypt_folder_name,
    decrypt_folder_name,
    inspect_folder_files,
    copy_and_encrypt_folders,
    rename_folders,
)


KEY = derive_key("test_password")


class TestFolderNameTransform:
    """資料夾名稱轉換測試"""

    def test_encrypt_folder_name(self):
        result = encrypt_folder_name("1234567820260206082130", KEY)
        assert len(result) == 27
        assert result[:14] == "20260206082130"
        assert result[14] == "_"
        assert result[15:23].isalpha()
        assert result[23:] == "5678"  # 末 4 碼保留

    def test_decrypt_folder_name_roundtrip(self):
        original = "1234567820260206082130"
        encrypted = encrypt_folder_name(original, KEY)
        decrypted = decrypt_folder_name(encrypted, KEY)
        assert decrypted == original

    def test_various_folders(self):
        originals = [
            "1234567820260206082130",
            "0000000120260115093000",
            "9999999920251231125900",
        ]
        for original in originals:
            encrypted = encrypt_folder_name(original, KEY)
            decrypted = decrypt_folder_name(encrypted, KEY)
            assert decrypted == original

    def test_last_four_preserved_in_folder_name(self):
        """資料夾加密後末 4 碼應與原始 ID 末 4 碼一致"""
        original = "1234567820260206082130"
        encrypted = encrypt_folder_name(original, KEY)
        assert encrypted[-4:] == "5678"


class TestScanFolders:
    """資料夾掃描測試"""

    @pytest.fixture
    def temp_dir(self, tmp_path):
        (tmp_path / "1234567820260206082130").mkdir()
        (tmp_path / "0000000120260115093000").mkdir()
        (tmp_path / "not_a_folder").mkdir()
        (tmp_path / "12345").mkdir()
        (tmp_path / "abcdefghijklmnopqrstuv").mkdir()  # 22碼但非數字
        (tmp_path / "somefile.txt").touch()
        return tmp_path

    def test_scan_for_encryption(self, temp_dir):
        results = scan_for_encryption(str(temp_dir))
        assert len(results) == 2
        assert "1234567820260206082130" in results
        assert "0000000120260115093000" in results

    def test_scan_for_decryption(self, temp_dir):
        (temp_dir / "20260206082130_AbCdEfGh1234").mkdir()
        (temp_dir / "20260115093000_XyZwAbCd0001").mkdir()
        results = scan_for_decryption(str(temp_dir))
        assert len(results) == 2

    def test_scan_nonexistent_dir(self):
        with pytest.raises(FileNotFoundError):
            scan_for_encryption("/nonexistent/path")


class TestInspectFolderFiles:
    """檔案類型偵測測試"""

    def test_inspect_all_types(self, tmp_path):
        folder = tmp_path / "1234567820260206082130"
        folder.mkdir()
        (folder / "data.jsonl").touch()
        (folder / "signal.edf").touch()
        (folder / "bio.acq").touch()
        (folder / "photo1.jpg").touch()
        (folder / "photo2.jpeg").touch()
        (folder / "notes.txt").touch()

        info = inspect_folder_files(str(folder))
        assert info["jpg_count"] == 2
        assert info["has_json"] is True
        assert info["has_edf"] is True
        assert info["has_acq"] is True
        assert info["other_count"] == 1

    def test_inspect_empty_folder(self, tmp_path):
        folder = tmp_path / "empty"
        folder.mkdir()
        info = inspect_folder_files(str(folder))
        assert info["jpg_count"] == 0
        assert info["has_json"] is False
        assert info["has_edf"] is False
        assert info["has_acq"] is False
        assert info["other_count"] == 0


class TestCopyAndEncryptFolders:
    """加密複製與檔案分流測試"""

    @pytest.fixture
    def setup_source(self, tmp_path):
        """建立含有各類檔案的來源資料夾"""
        source = tmp_path / "source"
        output = tmp_path / "output"
        source.mkdir()
        output.mkdir()

        folder_name = "1234567820260206082130"
        folder = source / folder_name
        folder.mkdir()

        # 建立各類檔案（jpg 檔名模擬實際格式：資料夾名_編號）
        (folder / "data.jsonl").write_text("test jsonl")
        (folder / "signal.edf").write_bytes(b"edf data")
        (folder / f"{folder_name}_1.jpg").write_bytes(b"jpg1")
        (folder / f"{folder_name}_3.jpg").write_bytes(b"jpg2")
        (folder / f"{folder_name}_6.jpeg").write_bytes(b"jpg3")
        (folder / "notes.txt").write_text("some notes")

        return source, output, folder_name

    def test_files_dispatched_to_correct_subdirs(self, setup_source):
        source, output, folder_name = setup_source

        results = copy_and_encrypt_folders(
            str(source), str(output), [folder_name], "test_password"
        )

        assert len(results) == 1
        r = results[0]
        assert r["success"] is True
        new_name = r["new_name"]

        # radar 應有 jsonl
        assert (output / "radar" / f"{new_name}.jsonl").exists()

        # MP36 應有 edf
        assert (output / "MP36" / f"{new_name}.edf").exists()

        # pic 應有加密名稱子資料夾，內含 加密名稱_原始編號.jpg（保留跳號）
        pic_dir = output / "pic" / new_name
        assert pic_dir.is_dir()
        assert (pic_dir / f"{new_name}_1.jpg").exists()
        assert (pic_dir / f"{new_name}_3.jpg").exists()
        assert (pic_dir / f"{new_name}_6.jpg").exists()

        # other 應有加密名稱子資料夾，內含 notes.txt
        other_dir = output / "other" / new_name
        assert other_dir.is_dir()
        assert (other_dir / "notes.txt").exists()

    def test_skip_already_processed(self, setup_source):
        source, output, folder_name = setup_source

        # 第一次加密
        results1 = copy_and_encrypt_folders(
            str(source), str(output), [folder_name], "test_password"
        )
        assert results1[0]["success"] is True

        # 第二次應跳過
        results2 = copy_and_encrypt_folders(
            str(source), str(output), [folder_name], "test_password"
        )
        assert results2[0]["skipped"] is True

    def test_acq_goes_to_mp36(self, tmp_path):
        source = tmp_path / "source"
        output = tmp_path / "output"
        source.mkdir()
        output.mkdir()

        folder_name = "1111222220260301100000"
        folder = source / folder_name
        folder.mkdir()
        (folder / "bio.acq").write_bytes(b"acq data")
        (folder / "dummy.jpg").write_bytes(b"jpg")

        results = copy_and_encrypt_folders(
            str(source), str(output), [folder_name], "test_password"
        )

        new_name = results[0]["new_name"]
        assert (output / "MP36" / f"{new_name}.acq").exists()

    def test_file_info_recorded(self, setup_source):
        source, output, folder_name = setup_source
        results = copy_and_encrypt_folders(
            str(source), str(output), [folder_name], "test_password"
        )
        info = results[0]["file_info"]
        assert info["jpg_count"] == 3
        assert info["has_json"] is True
        assert info["has_edf"] is True
        assert info["other_count"] == 1

    def test_no_other_files_no_other_dir(self, tmp_path):
        """若無其他類型檔案，不應建立 other 子資料夾"""
        source = tmp_path / "source"
        output = tmp_path / "output"
        source.mkdir()
        output.mkdir()

        folder_name = "5555666620260707120000"
        folder = source / folder_name
        folder.mkdir()
        (folder / "data.jsonl").write_text("jsonl")
        (folder / "photo.jpg").write_bytes(b"jpg")

        results = copy_and_encrypt_folders(
            str(source), str(output), [folder_name], "test_password"
        )
        new_name = results[0]["new_name"]
        assert not (output / "other" / new_name).exists()

    def test_no_jpg_files_no_pic_dir(self, tmp_path):
        """若無 jpg 檔案，不應建立 pic 子資料夾"""
        source = tmp_path / "source"
        output = tmp_path / "output"
        source.mkdir()
        output.mkdir()

        folder_name = "7777888820260808140000"
        folder = source / folder_name
        folder.mkdir()
        (folder / "data.jsonl").write_text("jsonl")
        (folder / "signal.edf").write_bytes(b"edf")

        results = copy_and_encrypt_folders(
            str(source), str(output), [folder_name], "test_password"
        )
        new_name = results[0]["new_name"]
        assert not (output / "pic" / new_name).exists()


class TestRenameFolders:
    """批次重命名測試"""

    def test_encrypt_rename(self, tmp_path):
        folder_name = "1234567820260206082130"
        (tmp_path / folder_name).mkdir()

        results = rename_folders(
            str(tmp_path), [folder_name], "password", "encrypt"
        )

        assert len(results) == 1
        assert results[0]["success"] is True
        assert not (tmp_path / folder_name).exists()
        assert (tmp_path / results[0]["new_name"]).exists()

    def test_decrypt_rename(self, tmp_path):
        original = "1234567820260206082130"
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
        folder_name = "1234567820260206082130"
        (tmp_path / folder_name).mkdir()

        target_name = encrypt_folder_name(folder_name, derive_key("password"))
        (tmp_path / target_name).mkdir()

        results = rename_folders(
            str(tmp_path), [folder_name], "password", "encrypt"
        )

        assert results[0]["success"] is False
        assert "已存在" in results[0]["error"]
