"""CSV 報告、表頭升級與備份測試"""

import csv

from src.csv_reporter import (
    SUMMARY_HEADER,
    PROCESSED_HEADER,
    generate_summary_csv,
    generate_processed_csv,
    upgrade_csv_header,
    backup_csvs,
)


def _result(group="patient", case_id="12345678", dt="20260206082130", success=True):
    return {
        "group": group,
        "old_name": case_id + dt,
        "new_name": dt + "_AbCdEfGh" + case_id[4:],
        "case_id": case_id,
        "datetime_str": dt,
        "success": success,
        "skipped": False,
        "error": None,
        "file_info": {
            "jpg_count": 2,
            "has_json": True,
            "has_edf": False,
            "has_acq": True,
            "other_count": 0,
        },
    }


def _read(path):
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.reader(f))


def _write(path, rows):
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        csv.writer(f).writerows(rows)


# 原始版（7e55c52）表頭
OLD_SUMMARY_HEADER = [
    "原始病例編號", "日期", "時分秒", "加密前檔名", "加密後檔名",
    "使用密碼", "JPG數量", "有JSON", "有EDF", "有ACQ", "加密時間",
]
OLD_SUMMARY_ROW = [
    '="00000001"', '="20260115"', '="093000"', '="0000000120260115093000"',
    "20260115093000_XyZwAbCd0001", "oldpw", "3", "是", "否", "否",
    "2026-01-15 10:00:00",
]
OLD_PROCESSED_HEADER = ["病例號碼", "日期", "時間", "資料夾名稱", "轉檔時間"]
OLD_PROCESSED_ROW = ['="00000001"', '="20260115"', '="093000"',
                     '="0000000120260115093000"', "2026-01-15 10:00:00"]


class TestSummaryCsv:
    def test_header_and_rows(self, tmp_path):
        path = tmp_path / "summary.csv"
        generate_summary_csv(
            [_result(), _result("control", "20000001", "20260405093015")],
            "pw",
            str(path),
        )
        rows = _read(path)
        assert rows[0] == SUMMARY_HEADER
        assert len(rows) == 3

        patient, control = rows[1], rows[2]
        assert patient[0] == "patient"
        assert patient[1] == '="12345678"'
        assert patient[2] == '="20260206"'
        assert patient[3] == '="082130"'
        assert patient[4] == '="1234567820260206082130"'
        assert patient[5] == "20260206082130_AbCdEfGh5678"
        assert patient[6] == "pw"
        assert patient[7] == "2"
        assert patient[8:11] == ["是", "否", "是"]

        assert control[0] == "control"
        assert control[1] == '="20000001"'
        assert control[4] == '="2000000120260405093015"'

    def test_skips_failed_results(self, tmp_path):
        path = tmp_path / "summary.csv"
        generate_summary_csv([_result(success=False)], "pw", str(path))
        assert _read(path) == [SUMMARY_HEADER]

    def test_append_keeps_single_header(self, tmp_path):
        path = tmp_path / "summary.csv"
        generate_summary_csv([_result()], "pw", str(path))
        generate_summary_csv([_result(case_id="22223333")], "pw", str(path))
        rows = _read(path)
        assert len(rows) == 3
        assert sum(1 for r in rows if r == SUMMARY_HEADER) == 1

    def test_migrates_old_header_on_append(self, tmp_path):
        """原始版表頭：重寫成新表頭，舊列群組補 patient，再追加新列"""
        path = tmp_path / "summary.csv"
        _write(path, [OLD_SUMMARY_HEADER, OLD_SUMMARY_ROW])

        generate_summary_csv([_result("control", "20000001")], "pw", str(path))

        rows = _read(path)
        assert rows[0] == SUMMARY_HEADER
        assert len(rows) == 3
        assert rows[1] == ["patient"] + OLD_SUMMARY_ROW
        assert rows[2][0] == "control"
        assert not (tmp_path / "summary.csv.tmp").exists()


class TestProcessedCsv:
    def test_written_to_source_dir(self, tmp_path):
        returned = generate_processed_csv(
            [_result(), _result("control", "20000001", "20260405093015")],
            str(tmp_path),
        )
        path = tmp_path / "processed.csv"
        assert returned == str(path)
        rows = _read(path)
        assert rows[0] == PROCESSED_HEADER
        assert rows[1][:5] == [
            "patient", '="12345678"', '="20260206"', '="082130"', '="1234567820260206082130"',
        ]
        assert rows[2][:5] == [
            "control", '="20000001"', '="20260405"', '="093015"', '="2000000120260405093015"',
        ]

    def test_migrates_old_header_on_append(self, tmp_path):
        path = tmp_path / "processed.csv"
        _write(path, [OLD_PROCESSED_HEADER, OLD_PROCESSED_ROW])

        generate_processed_csv([_result()], str(tmp_path))

        rows = _read(path)
        assert rows[0] == PROCESSED_HEADER
        assert rows[1] == ["patient"] + OLD_PROCESSED_ROW
        assert rows[2][0] == "patient"


class TestUpgradeCsvHeader:
    def test_upgrade_old_summary(self, tmp_path):
        path = tmp_path / "summary.csv"
        _write(path, [OLD_SUMMARY_HEADER, OLD_SUMMARY_ROW, OLD_SUMMARY_ROW])
        assert upgrade_csv_header(str(path), SUMMARY_HEADER) is True
        rows = _read(path)
        assert rows[0] == SUMMARY_HEADER
        assert rows[1:] == [["patient"] + OLD_SUMMARY_ROW] * 2

    def test_upgrade_old_processed(self, tmp_path):
        path = tmp_path / "processed.csv"
        _write(path, [OLD_PROCESSED_HEADER, OLD_PROCESSED_ROW])
        assert upgrade_csv_header(str(path), PROCESSED_HEADER) is True
        assert _read(path) == [PROCESSED_HEADER, ["patient"] + OLD_PROCESSED_ROW]

    def test_drops_extra_columns(self, tmp_path):
        """多餘欄位（例如中間版本的身份證號欄）會被丟棄，其餘依欄名對應"""
        path = tmp_path / "summary.csv"
        _write(path, [["群組", "身份證號"] + OLD_SUMMARY_HEADER, ["control", "A123456789"] + OLD_SUMMARY_ROW])
        assert upgrade_csv_header(str(path), SUMMARY_HEADER) is True
        assert _read(path) == [SUMMARY_HEADER, ["control"] + OLD_SUMMARY_ROW]

    def test_noop_when_already_current_or_missing(self, tmp_path):
        path = tmp_path / "summary.csv"
        assert upgrade_csv_header(str(path), SUMMARY_HEADER) is False  # 不存在
        assert not path.exists()
        _write(path, [SUMMARY_HEADER])
        assert upgrade_csv_header(str(path), SUMMARY_HEADER) is False  # 已是新版
        assert _read(path) == [SUMMARY_HEADER]


class TestBackup:
    def test_keeps_only_latest_per_kind_and_source(self, tmp_path):
        backup = tmp_path / "bk"
        backup.mkdir()
        src = tmp_path / "src"
        src.mkdir()
        summary = tmp_path / "summary.csv"
        summary.write_text("summary-now")
        processed = src / "processed.csv"
        processed.write_text("processed-now")

        (backup / "summary_20260101_000000.csv").write_text("old summary")
        (backup / "processed_src_20260101_000000.csv").write_text("old same source")
        (backup / "processed_20260101_000000.csv").write_text("legacy naming")
        (backup / "processed_other_20260101_000000.csv").write_text("other source")
        (backup / "notes.txt").write_text("unrelated")

        written = backup_csvs(str(summary), str(processed), backup_dir=backup)

        assert written["summary"].name.startswith("summary_")
        assert written["summary"].read_text() == "summary-now"
        assert written["processed"].name.startswith("processed_src_")
        assert written["processed"].read_text() == "processed-now"

        remaining = sorted(p.name for p in backup.iterdir())
        assert remaining == sorted([
            written["summary"].name,
            written["processed"].name,
            "processed_other_20260101_000000.csv",  # 其他來源夾的備份保留
            "notes.txt",  # 非備份檔不動
        ])

    def test_missing_sources_skipped_but_dir_created(self, tmp_path):
        backup = tmp_path / "bk"
        written = backup_csvs(
            str(tmp_path / "none.csv"), str(tmp_path / "none2.csv"), backup_dir=backup
        )
        assert written == {}
        assert backup.is_dir()
