"""資料夾掃描、格式辨識、加密複製與重命名邏輯測試"""

import pytest
from src.crypto import derive_key
from src.folder_scanner import (
    classify_folder,
    parse_folder_name,
    scan_for_encryption,
    scan_for_decryption,
    encrypt_folder_name,
    decrypt_folder_name,
    inspect_folder_files,
    copy_and_encrypt_folders,
    rename_folders,
)


KEY = derive_key("test_password")

PATIENT = "1234567820260206082130"
NATIONAL_ID = "A123456789"
CONTROL = NATIONAL_ID + PATIENT


class TestClassifyAndParse:
    """群組辨識與名稱拆解測試"""

    def test_patient(self):
        assert classify_folder(PATIENT) == "patient"
        assert parse_folder_name(PATIENT) == {
            "group": "patient",
            "national_id": "",
            "case_id": "12345678",
            "datetime_str": "20260206082130",
            "core": PATIENT,
        }

    def test_control(self):
        assert classify_folder(CONTROL) == "control"
        parsed = parse_folder_name(CONTROL)
        assert parsed["group"] == "control"
        assert parsed["national_id"] == NATIONAL_ID
        assert parsed["case_id"] == "12345678"
        assert parsed["datetime_str"] == "20260206082130"
        assert parsed["core"] == PATIENT

    def test_control_accepts_lowercase_and_two_letter_prefix(self):
        assert classify_folder("a123456789" + PATIENT) == "control"
        assert classify_folder("AB12345678" + PATIENT) == "control"

    @pytest.mark.parametrize(
        "name",
        [
            "12345",  # 太短
            "abcdefghijklmnopqrstuv",  # 22 碼但非數字
            "1234567890" + PATIENT,  # 前 10 碼全數字，不是身份證號
            "A12345678" + PATIENT,  # 身份證號只有 9 碼
            "A1234567890" + PATIENT,  # 身份證號 11 碼
            "20260206082130_AbCdEfGh1234",  # 加密格式
        ],
    )
    def test_invalid(self, name):
        assert classify_folder(name) is None
        with pytest.raises(ValueError):
            parse_folder_name(name)


class TestFolderNameTransform:
    """資料夾名稱轉換測試"""

    def test_encrypt_patient(self):
        result = encrypt_folder_name(PATIENT, KEY)
        assert len(result) == 27
        assert result[:14] == "20260206082130"
        assert result[14] == "_"
        assert result[15:23].isalpha()
        assert result[23:] == "5678"  # 末 4 碼保留

    def test_encrypt_control(self):
        """control = 日期時間 + _ + 加密身份證號（10 英文 + 末 4 碼原文）；病歷號不進名稱"""
        encrypted = encrypt_folder_name(CONTROL, KEY)
        assert len(encrypted) == 29
        assert encrypted[:14] == "20260206082130"
        assert encrypted[14] == "_"
        assert encrypted[15:25].isalpha()
        assert encrypted[25:] == "6789"  # 身份證號末 4 碼原文
        assert NATIONAL_ID not in encrypted
        assert NATIONAL_ID[:6] not in encrypted
        assert "12345678" not in encrypted  # 病歷號不進名稱
        assert encrypted != encrypt_folder_name(PATIENT, KEY)

    def test_decrypt_roundtrip_patient(self):
        encrypted = encrypt_folder_name(PATIENT, KEY)
        assert decrypt_folder_name(encrypted, KEY) == PATIENT

    def test_decrypt_control_returns_national_id_and_datetime(self):
        """control 還原為身份證號 + 日期時間（24 碼）；病歷號需查 summary.csv"""
        encrypted = encrypt_folder_name(CONTROL, KEY)
        assert decrypt_folder_name(encrypted, KEY) == NATIONAL_ID + "20260206082130"

    def test_various_folders(self):
        originals = [
            "1234567820260206082130",
            "0000000120260115093000",
            "9999999920251231125900",
        ]
        for original in originals:
            encrypted = encrypt_folder_name(original, KEY)
            assert decrypt_folder_name(encrypted, KEY) == original

    def test_invalid_name_raises(self):
        with pytest.raises(ValueError):
            encrypt_folder_name("not_a_folder", KEY)


class TestScanFolders:
    """資料夾掃描測試"""

    @pytest.fixture
    def temp_dir(self, tmp_path):
        (tmp_path / PATIENT).mkdir()
        (tmp_path / "0000000120260115093000").mkdir()
        (tmp_path / CONTROL).mkdir()
        (tmp_path / "not_a_folder").mkdir()
        (tmp_path / "12345").mkdir()
        (tmp_path / "abcdefghijklmnopqrstuv").mkdir()  # 22碼但非數字
        (tmp_path / "somefile.txt").touch()
        return tmp_path

    def test_scan_for_encryption_finds_both_groups(self, temp_dir):
        results = scan_for_encryption(str(temp_dir))
        assert len(results) == 3
        assert PATIENT in results
        assert "0000000120260115093000" in results
        assert CONTROL in results

    def test_scan_for_decryption(self, temp_dir):
        (temp_dir / "20260206082130_AbCdEfGh1234").mkdir()
        (temp_dir / "20260115093000_XyZwAbCd0001").mkdir()
        (temp_dir / "20260206082130_qWeRtYuIoP6789").mkdir()  # control（29 碼）
        (temp_dir / "20260206082130_qWeRtYuIo6789").mkdir()  # 9 英文，兩種格式都不是，不收
        results = scan_for_decryption(str(temp_dir))
        assert len(results) == 3
        assert "20260206082130_qWeRtYuIoP6789" in results

    def test_scan_nonexistent_dir(self):
        with pytest.raises(FileNotFoundError):
            scan_for_encryption("/nonexistent/path")


class TestInspectFolderFiles:
    """檔案類型偵測測試"""

    def test_inspect_all_types(self, tmp_path):
        folder = tmp_path / PATIENT
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


def _make_case(source, folder_name):
    """建立含各類檔案的來源案例資料夾（jpg 檔名模擬實際格式：資料夾名_編號）"""
    folder = source / folder_name
    folder.mkdir()
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
        _make_case(source, PATIENT)

        results = copy_and_encrypt_folders(
            str(source), str(output), [PATIENT], "test_password"
        )

        assert len(results) == 1
        r = results[0]
        assert r["success"] is True
        assert r["group"] == "patient"
        assert r["national_id"] == ""
        assert r["case_id"] == "12345678"
        assert r["datetime_str"] == "20260206082130"
        new_name = r["new_name"]

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
        _make_case(source, CONTROL)

        results = copy_and_encrypt_folders(
            str(source), str(output), [CONTROL], "test_password"
        )

        r = results[0]
        assert r["success"] is True
        assert r["group"] == "control"
        assert r["national_id"] == NATIONAL_ID
        assert r["case_id"] == "12345678"
        assert r["datetime_str"] == "20260206082130"
        new_name = r["new_name"]
        assert len(new_name) == 29
        assert new_name[25:] == "6789"  # 身份證號末 4 碼原文
        assert NATIONAL_ID not in new_name

        base = output / "control"
        assert (base / "radar" / f"{new_name}.jsonl").exists()
        assert (base / "MP36" / f"{new_name}.edf").exists()
        assert (base / "pic" / new_name / f"{new_name}_1.jpg").exists()
        assert (base / "other" / new_name / "notes.txt").exists()
        assert not (output / "patient").exists()

    def test_mixed_groups_go_to_separate_trees(self, dirs):
        """同病歷號同時間的 patient 與 control：token 不同（病歷號 vs 身份證號），各自進自己的群組樹"""
        source, output = dirs
        _make_case(source, PATIENT)
        _make_case(source, CONTROL)

        results = copy_and_encrypt_folders(
            str(source), str(output), [PATIENT, CONTROL], "test_password"
        )

        assert all(r["success"] for r in results)
        by_group = {r["group"]: r for r in results}
        patient_new = by_group["patient"]["new_name"]
        control_new = by_group["control"]["new_name"]
        assert patient_new != control_new
        assert patient_new[:15] == control_new[:15]  # 同日期時間段
        assert len(patient_new) == 27 and len(control_new) == 29
        assert (output / "patient" / "radar" / f"{patient_new}.jsonl").exists()
        assert (output / "control" / "radar" / f"{control_new}.jsonl").exists()

    def test_skip_already_processed(self, dirs):
        source, output = dirs
        _make_case(source, PATIENT)

        results1 = copy_and_encrypt_folders(
            str(source), str(output), [PATIENT], "test_password"
        )
        assert results1[0]["success"] is True

        results2 = copy_and_encrypt_folders(
            str(source), str(output), [PATIENT], "test_password"
        )
        assert results2[0]["skipped"] is True
        assert results2[0]["success"] is False

    def test_acq_goes_to_mp36(self, dirs):
        source, output = dirs
        folder_name = "1111222220260301100000"
        folder = source / folder_name
        folder.mkdir()
        (folder / "bio.acq").write_bytes(b"acq data")
        (folder / "dummy.jpg").write_bytes(b"jpg")

        results = copy_and_encrypt_folders(
            str(source), str(output), [folder_name], "test_password"
        )

        new_name = results[0]["new_name"]
        assert (output / "patient" / "MP36" / f"{new_name}.acq").exists()

    def test_file_info_recorded(self, dirs):
        source, output = dirs
        _make_case(source, PATIENT)
        results = copy_and_encrypt_folders(
            str(source), str(output), [PATIENT], "test_password"
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
        folder = source / folder_name
        folder.mkdir()
        (folder / "data.jsonl").write_text("jsonl")
        (folder / "photo.jpg").write_bytes(b"jpg")

        results = copy_and_encrypt_folders(
            str(source), str(output), [folder_name], "test_password"
        )
        new_name = results[0]["new_name"]
        assert not (output / "patient" / "other" / new_name).exists()

    def test_no_jpg_files_no_pic_dir(self, dirs):
        """若無 jpg 檔案，不應建立 pic/<加密名> 子資料夾"""
        source, output = dirs
        folder_name = "7777888820260808140000"
        folder = source / folder_name
        folder.mkdir()
        (folder / "data.jsonl").write_text("jsonl")
        (folder / "signal.edf").write_bytes(b"edf")

        results = copy_and_encrypt_folders(
            str(source), str(output), [folder_name], "test_password"
        )
        new_name = results[0]["new_name"]
        assert not (output / "patient" / "pic" / new_name).exists()

    def test_invalid_name_reported_as_error(self, dirs):
        source, output = dirs
        results = copy_and_encrypt_folders(
            str(source), str(output), ["bad_name"], "test_password"
        )
        assert results[0]["success"] is False
        assert results[0]["skipped"] is False
        assert "格式不符" in results[0]["error"]
        assert not (output / "patient").exists()
        assert not (output / "control").exists()


class TestRenameFolders:
    """批次重命名測試"""

    def test_encrypt_rename(self, tmp_path):
        (tmp_path / PATIENT).mkdir()

        results = rename_folders(str(tmp_path), [PATIENT], "password", "encrypt")

        assert len(results) == 1
        assert results[0]["success"] is True
        assert not (tmp_path / PATIENT).exists()
        assert (tmp_path / results[0]["new_name"]).exists()

    def test_decrypt_rename(self, tmp_path):
        password = "roundtrip"
        (tmp_path / PATIENT).mkdir()
        enc_results = rename_folders(str(tmp_path), [PATIENT], password, "encrypt")
        encrypted_name = enc_results[0]["new_name"]

        dec_results = rename_folders(
            str(tmp_path), [encrypted_name], password, "decrypt"
        )

        assert dec_results[0]["success"] is True
        assert dec_results[0]["new_name"] == PATIENT
        assert (tmp_path / PATIENT).exists()

    def test_target_already_exists(self, tmp_path):
        (tmp_path / PATIENT).mkdir()

        target_name = encrypt_folder_name(PATIENT, derive_key("password"))
        (tmp_path / target_name).mkdir()

        results = rename_folders(str(tmp_path), [PATIENT], "password", "encrypt")

        assert results[0]["success"] is False
        assert "已存在" in results[0]["error"]
