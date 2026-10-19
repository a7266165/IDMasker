"""資料夾掃描、加密複製與重命名邏輯測試"""

import pytest
from src.crypto import derive_key
from src.folder_scanner import (
    LayoutError,
    split_case_name,
    find_legacy_case_dirs,
    scan_for_encryption,
    scan_for_decryption,
    encrypt_folder_name,
    decrypt_folder_name,
    inspect_folder_files,
    copy_and_encrypt_folders,
    rename_folders,
)


KEY = derive_key("test_password")

CASE_A = "1234567820260206082130"
CASE_B = "0000000120260115093000"
CASE_C = "2000000120260405093015"


class TestSplitCaseName:
    def test_split(self):
        assert split_case_name(CASE_A) == ("12345678", "20260206082130")

    @pytest.mark.parametrize("name", ["12345", "abcdefghijklmnopqrstuv", "A123456789" + CASE_A])
    def test_invalid(self, name):
        with pytest.raises(ValueError):
            split_case_name(name)


class TestFolderNameTransform:
    """資料夾名稱轉換測試"""

    def test_encrypt_folder_name(self):
        result = encrypt_folder_name(CASE_A, KEY)
        assert len(result) == 27
        assert result[:14] == "20260206082130"
        assert result[14] == "_"
        assert result[15:23].isalpha()
        assert result[23:] == "5678"  # 末 4 碼保留

    def test_decrypt_folder_name_roundtrip(self):
        encrypted = encrypt_folder_name(CASE_A, KEY)
        assert decrypt_folder_name(encrypted, KEY) == CASE_A

    def test_various_folders(self):
        for original in [CASE_A, CASE_B, "9999999920251231125900", CASE_C]:
            encrypted = encrypt_folder_name(original, KEY)
            assert decrypt_folder_name(encrypted, KEY) == original

    def test_invalid_name_raises(self):
        with pytest.raises(ValueError):
            encrypt_folder_name("not_a_folder", KEY)
        with pytest.raises(ValueError):
            decrypt_folder_name("20260206082130_AbCdEfGh123", KEY)


class TestScanFolders:
    """來源夾掃描：patient/ 與 control/ 分層"""

    @pytest.fixture
    def source(self, tmp_path):
        (tmp_path / "patient" / CASE_A).mkdir(parents=True)
        (tmp_path / "patient" / CASE_B).mkdir()
        (tmp_path / "patient" / "not_a_case").mkdir()
        (tmp_path / "control" / CASE_C).mkdir(parents=True)
        (tmp_path / "control" / "abcdefghijklmnopqrstuv").mkdir()  # 22碼但非數字
        (tmp_path / "somefile.txt").touch()
        (tmp_path / "processed.csv").touch()
        (tmp_path / "other_dir").mkdir()  # 頂層非 22 碼資料夾：忽略
        return tmp_path

    def test_scan_groups_by_location(self, source):
        cases = scan_for_encryption(str(source))
        assert cases == [
            ("patient", CASE_B),
            ("patient", CASE_A),
            ("control", CASE_C),
        ]

    def test_scan_only_patient_dir(self, tmp_path):
        (tmp_path / "patient" / CASE_A).mkdir(parents=True)
        assert scan_for_encryption(str(tmp_path)) == [("patient", CASE_A)]

    def test_scan_empty_source(self, tmp_path):
        assert scan_for_encryption(str(tmp_path)) == []

    def test_legacy_top_level_case_raises(self, tmp_path):
        """頂層直接放 22 碼資料夾（舊版擺法）：直接報錯，不往下跑"""
        (tmp_path / "patient" / CASE_A).mkdir(parents=True)
        (tmp_path / CASE_B).mkdir()
        assert find_legacy_case_dirs(str(tmp_path)) == [CASE_B]
        with pytest.raises(LayoutError, match="頂層直接放了 1 個"):
            scan_for_encryption(str(tmp_path))

    def test_scan_nonexistent_dir(self):
        with pytest.raises(FileNotFoundError):
            scan_for_encryption("/nonexistent/path")

    def test_scan_for_decryption(self, tmp_path):
        (tmp_path / "20260206082130_AbCdEfGh1234").mkdir()
        (tmp_path / "20260115093000_XyZwAbCd0001").mkdir()
        (tmp_path / "20260206082130_AbCdEfGh123").mkdir()  # 不符
        (tmp_path / CASE_A).mkdir()  # 未加密
        results = scan_for_decryption(str(tmp_path))
        assert results == ["20260115093000_XyZwAbCd0001", "20260206082130_AbCdEfGh1234"]


class TestInspectFolderFiles:
    """檔案類型偵測測試"""

    def test_inspect_all_types(self, tmp_path):
        folder = tmp_path / CASE_A
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


def _make_case(source, group, folder_name):
    """建立含各類檔案的案例資料夾（jpg 檔名模擬實際格式：資料夾名_編號）"""
    folder = source / group / folder_name
    folder.mkdir(parents=True)
    (folder / "data.jsonl").write_text("test jsonl")
    (folder / "signal.edf").write_bytes(b"edf data")
    (folder / f"{folder_name}_1.jpg").write_bytes(b"jpg1")
    (folder / f"{folder_name}_3.jpg").write_bytes(b"jpg2")
    (folder / f"{folder_name}_6.jpeg").write_bytes(b"jpg3")
    (folder / "notes.txt").write_text("some notes")
    return folder


class TestCopyAndEncryptFolders:
    """加密複製、群組分流與檔案分流測試"""

    @pytest.fixture
    def dirs(self, tmp_path):
        source = tmp_path / "source"
        output = tmp_path / "output"
        source.mkdir()
        output.mkdir()
        return source, output

    def test_patient_dispatched_under_patient_dir(self, dirs):
        source, output = dirs
        _make_case(source, "patient", CASE_A)

        results = copy_and_encrypt_folders(
            str(source), str(output), [("patient", CASE_A)], "test_password"
        )

        assert len(results) == 1
        r = results[0]
        assert r["success"] is True
        assert r["group"] == "patient"
        assert r["case_id"] == "12345678"
        assert r["datetime_str"] == "20260206082130"
        new_name = r["new_name"]
        assert len(new_name) == 27

        base = output / "patient"
        assert (base / "radar" / f"{new_name}.jsonl").exists()
        assert (base / "MP36" / f"{new_name}.edf").exists()

        pic_dir = base / "pic" / new_name
        assert pic_dir.is_dir()
        assert (pic_dir / f"{new_name}_1.jpg").exists()
        assert (pic_dir / f"{new_name}_3.jpg").exists()
        assert (pic_dir / f"{new_name}_6.jpg").exists()

        other_dir = base / "other" / new_name
        assert other_dir.is_dir()
        assert (other_dir / "notes.txt").exists()

        # 沒處理 control，就不建立 control 樹
        assert not (output / "control").exists()

    def test_control_dispatched_under_control_dir(self, dirs):
        source, output = dirs
        _make_case(source, "control", CASE_C)

        results = copy_and_encrypt_folders(
            str(source), str(output), [("control", CASE_C)], "test_password"
        )

        r = results[0]
        assert r["success"] is True
        assert r["group"] == "control"
        new_name = r["new_name"]
        assert new_name == encrypt_folder_name(CASE_C, KEY)  # 與 patient 同一套規則

        base = output / "control"
        assert (base / "radar" / f"{new_name}.jsonl").exists()
        assert (base / "MP36" / f"{new_name}.edf").exists()
        assert (base / "pic" / new_name / f"{new_name}_1.jpg").exists()
        assert (base / "other" / new_name / "notes.txt").exists()
        assert not (output / "patient").exists()

    def test_same_name_in_both_groups_goes_to_separate_trees(self, dirs):
        """同名案例同時在 patient/ 與 control/：加密名相同，但分屬不同群組樹，互不影響"""
        source, output = dirs
        _make_case(source, "patient", CASE_A)
        _make_case(source, "control", CASE_A)

        results = copy_and_encrypt_folders(
            str(source), str(output), [("patient", CASE_A), ("control", CASE_A)], "test_password"
        )

        assert all(r["success"] for r in results)
        new_name = results[0]["new_name"]
        assert results[1]["new_name"] == new_name
        assert (output / "patient" / "radar" / f"{new_name}.jsonl").exists()
        assert (output / "control" / "radar" / f"{new_name}.jsonl").exists()

    def test_skip_already_processed(self, dirs):
        source, output = dirs
        _make_case(source, "patient", CASE_A)

        results1 = copy_and_encrypt_folders(
            str(source), str(output), [("patient", CASE_A)], "test_password"
        )
        assert results1[0]["success"] is True

        results2 = copy_and_encrypt_folders(
            str(source), str(output), [("patient", CASE_A)], "test_password"
        )
        assert results2[0]["skipped"] is True
        assert results2[0]["success"] is False

    def test_acq_goes_to_mp36(self, dirs):
        source, output = dirs
        folder_name = "1111222220260301100000"
        folder = source / "patient" / folder_name
        folder.mkdir(parents=True)
        (folder / "bio.acq").write_bytes(b"acq data")
        (folder / "dummy.jpg").write_bytes(b"jpg")

        results = copy_and_encrypt_folders(
            str(source), str(output), [("patient", folder_name)], "test_password"
        )

        new_name = results[0]["new_name"]
        assert (output / "patient" / "MP36" / f"{new_name}.acq").exists()

    def test_file_info_recorded(self, dirs):
        source, output = dirs
        _make_case(source, "patient", CASE_A)
        results = copy_and_encrypt_folders(
            str(source), str(output), [("patient", CASE_A)], "test_password"
        )
        info = results[0]["file_info"]
        assert info["jpg_count"] == 3
        assert info["has_json"] is True
        assert info["has_edf"] is True
        assert info["other_count"] == 1

    def test_no_other_files_no_other_dir(self, dirs):
        """若無其他類型檔案，不應建立 other/<加密名> 子資料夾"""
        source, output = dirs
        folder_name = "5555666620260707120000"
        folder = source / "patient" / folder_name
        folder.mkdir(parents=True)
        (folder / "data.jsonl").write_text("jsonl")
        (folder / "photo.jpg").write_bytes(b"jpg")

        results = copy_and_encrypt_folders(
            str(source), str(output), [("patient", folder_name)], "test_password"
        )
        new_name = results[0]["new_name"]
        assert not (output / "patient" / "other" / new_name).exists()

    def test_no_jpg_files_no_pic_dir(self, dirs):
        """若無 jpg 檔案，不應建立 pic/<加密名> 子資料夾"""
        source, output = dirs
        folder_name = "7777888820260808140000"
        folder = source / "patient" / folder_name
        folder.mkdir(parents=True)
        (folder / "data.jsonl").write_text("jsonl")
        (folder / "signal.edf").write_bytes(b"edf")

        results = copy_and_encrypt_folders(
            str(source), str(output), [("patient", folder_name)], "test_password"
        )
        new_name = results[0]["new_name"]
        assert not (output / "patient" / "pic" / new_name).exists()

    def test_invalid_name_and_unknown_group_reported(self, dirs):
        source, output = dirs
        results = copy_and_encrypt_folders(
            str(source), str(output), [("patient", "bad_name"), ("other", CASE_A)], "test_password"
        )
        assert [r["success"] for r in results] == [False, False]
        assert "格式不符" in results[0]["error"]
        assert "未知群組" in results[1]["error"]
        assert not (output / "patient").exists()

    def test_missing_source_folder_reported(self, dirs):
        source, output = dirs
        (source / "patient").mkdir()
        results = copy_and_encrypt_folders(
            str(source), str(output), [("patient", CASE_A)], "test_password"
        )
        assert results[0]["success"] is False
        assert "找不到來源資料夾" in results[0]["error"]


class TestRenameFolders:
    """批次重命名測試（單一資料夾內）"""

    def test_encrypt_rename(self, tmp_path):
        (tmp_path / CASE_A).mkdir()

        results = rename_folders(str(tmp_path), [CASE_A], "password", "encrypt")

        assert len(results) == 1
        assert results[0]["success"] is True
        assert not (tmp_path / CASE_A).exists()
        assert (tmp_path / results[0]["new_name"]).exists()

    def test_decrypt_rename(self, tmp_path):
        password = "roundtrip"
        (tmp_path / CASE_A).mkdir()
        enc_results = rename_folders(str(tmp_path), [CASE_A], password, "encrypt")
        encrypted_name = enc_results[0]["new_name"]

        dec_results = rename_folders(
            str(tmp_path), [encrypted_name], password, "decrypt"
        )

        assert dec_results[0]["success"] is True
        assert dec_results[0]["new_name"] == CASE_A
        assert (tmp_path / CASE_A).exists()

    def test_target_already_exists(self, tmp_path):
        (tmp_path / CASE_A).mkdir()

        target_name = encrypt_folder_name(CASE_A, derive_key("password"))
        (tmp_path / target_name).mkdir()

        results = rename_folders(str(tmp_path), [CASE_A], "password", "encrypt")

        assert results[0]["success"] is False
        assert "已存在" in results[0]["error"]
