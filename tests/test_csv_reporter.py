"""CSV 報告、表頭升級與備份測試"""

import csv

from src.csv_reporter import (
    SUMMARY_HEADER,
    PROCESSED_HEADER,
    generate_summary_csv,
    generate_processed_csv,
    backup_csvs,
)


def _result(
    group="patient",
    national_id="",
    case_id="12345678",
    dt="20260206082130",
    success=True,
):
    return {
        "old_name": national_id + case_id + dt,
        "new_name": dt + "_AbCdEfGh" + case_id[4:],
        "group": group,
        "national_id": national_id,
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


OLD_SUMMARY_HEADER = [
    "原始病例編號", "日期", "時分秒", "加密前檔名", "加密後檔名",
    "使用密碼", "JPG數量", "有JSON", "有EDF", "有ACQ", "加密時間",
]
OLD_SUMMARY_ROW = [
    '="00000001"', '="20260115"', '="093000"', '="0000000120260115093000"',
    "20260115093000_XyZwAbCd0001", "oldpw", "3", "是", "否", "否",
    "2026-01-15 10:00:00",
]


class TestSummaryCsv:
    def test_header_and_rows(self, tmp_path):
        path = tmp_path / "summary.csv"
        generate_summary_csv(
            [_result(), _result("control", "A123456789", "87654321")],
            "pw",
            str(path),
        )
        rows = _read(path)
        assert rows[0] == SUMMARY_HEADER
        assert len(rows) == 3

        patient, control = rows[1], rows[2]
        assert patient[0] == "patient"
        assert patient[1] == ""
        assert patient[2] == '="12345678"'
        assert patient[3] == '="20260206"'
        assert patient[4] == '="082130"'
        assert patient[5] == '="1234567820260206082130"'
        assert patient[6] == "20260206082130_AbCdEfGh5678"
        assert patient[7] == "pw"
        assert patient[8] == "2"
        assert patient[9:12] == ["是", "否", "是"]

        assert control[0] == "control"
        assert control[1] == "A123456789"
        assert control[2] == '="87654321"'
        assert control[5] == '="A1234567898765432120260206082130"'

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

    def test_migrates_old_header(self, tmp_path):
        """舊版表頭：重寫成新表頭，舊列群組補 patient、身份證號留空，再追加新列"""
        path = tmp_path / "summary.csv"
        _write(path, [OLD_SUMMARY_HEADER, OLD_SUMMARY_ROW])

        generate_summary_csv([_result("control", "A123456789")], "pw", str(path))

        rows = _read(path)
        assert rows[0] == SUMMARY_HEADER
        assert len(rows) == 3
        assert rows[1] == ["patient", ""] + OLD_SUMMARY_ROW
        assert rows[2][0] == "control"
        assert rows[2][1] == "A123456789"
        assert not (tmp_path / "summary.csv.tmp").exists()


class TestProcessedCsv:
    def test_written_to_source_dir(self, tmp_path):
        returned = generate_processed_csv(
            [_result(), _result("control", "B987654321", "11112222")],
            str(tmp_path),
        )
        path = tmp_path / "processed.csv"
        assert returned == str(path)
        rows = _read(path)
        assert rows[0] == PROCESSED_HEADER
        assert rows[1][:6] == [
            "patient", "", '="12345678"', '="20260206"', '="082130"',
            '="1234567820260206082130"',
        ]
        assert rows[2][:6] == [
            "control", "B987654321", '="11112222"', '="20260206"', '="082130"',
            '="B9876543211111222220260206082130"',
        ]

    def test_migrates_old_header(self, tmp_path):
        path = tmp_path / "processed.csv"
        old_header = ["病例號碼", "日期", "時間", "資料夾名稱", "轉檔時間"]
        old_row = ['="00000001"', '="20260115"', '="093000"',
                   '="0000000120260115093000"', "2026-01-15 10:00:00"]
        _write(path, [old_header, old_row])

        generate_processed_csv([_result()], str(tmp_path))

        rows = _read(path)
        assert rows[0] == PROCESSED_HEADER
        assert rows[1] == ["patient", ""] + old_row
        assert rows[2][0] == "patient"


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
