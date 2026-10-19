"""完整流程（pipeline）與 CLI 進入點測試"""

import csv
import json

import pytest

from src.main import main
from src.pipeline import run_encryption
from src.csv_reporter import SUMMARY_HEADER
from src.folder_scanner import LayoutError

PATIENT = "1234567820260206082130"
CONTROL = "2000000120260405093015"


def _make_source(tmp_path):
    source = tmp_path / "source"
    for group, name in (("patient", PATIENT), ("control", CONTROL)):
        folder = source / group / name
        folder.mkdir(parents=True)
        (folder / "data.jsonl").write_text("x")
        (folder / f"{name}_1.jpg").write_bytes(b"jpg")
    (source / "decoy").mkdir()
    return source


def _read(path):
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.reader(f))


class TestRunEncryption:
    def test_full_run_then_rerun_skips(self, tmp_path):
        source = _make_source(tmp_path)
        output = tmp_path / "out"
        csv_dir = tmp_path / "csv"  # 不預先建立，流程應自行 mkdir
        backup = tmp_path / "backup"

        summary = run_encryption(
            str(source), str(output), str(csv_dir), "pw", backup_dir=backup
        )

        assert summary["success_count"] == 2
        assert summary["skipped_count"] == 0
        assert summary["fail_count"] == 0
        assert summary["backup_error"] is None
        assert [(r["group"], r["old_name"]) for r in summary["results"]] == [
            ("patient", PATIENT), ("control", CONTROL),
        ]

        rows = _read(csv_dir / "summary.csv")
        assert rows[0] == SUMMARY_HEADER
        assert len(rows) == 3
        assert (source / "processed.csv").exists()
        assert summary["processed_csv"] == str(source / "processed.csv")

        backups = sorted(p.name for p in backup.iterdir())
        assert len(backups) == 2
        assert any(n.startswith("summary_") for n in backups)
        assert any(n.startswith("processed_source_") for n in backups)
        assert set(summary["backup"]) == {"summary", "processed"}

        # 第二次：全部跳過，不寫 CSV、不備份
        again = run_encryption(
            str(source), str(output), str(csv_dir), "pw", backup_dir=backup
        )
        assert again["success_count"] == 0
        assert again["skipped_count"] == 2
        assert again["processed_csv"] is None
        assert again["backup"] == {}
        assert len(_read(csv_dir / "summary.csv")) == 3
        assert sorted(p.name for p in backup.iterdir()) == backups

    def test_explicit_case_subset(self, tmp_path):
        source = _make_source(tmp_path)
        summary = run_encryption(
            str(source), str(tmp_path / "out"), str(tmp_path / "csv"), "pw",
            cases=[("control", CONTROL)], backup_dir=tmp_path / "backup",
        )
        assert [r["old_name"] for r in summary["results"]] == [CONTROL]
        assert not (tmp_path / "out" / "patient").exists()

    def test_legacy_layout_raises_before_anything_is_written(self, tmp_path):
        source = _make_source(tmp_path)
        (source / "0000000120260115093000").mkdir()  # 頂層 22 碼資料夾
        with pytest.raises(LayoutError):
            run_encryption(str(source), str(tmp_path / "out"), str(tmp_path / "csv"), "pw")
        assert not (tmp_path / "out").exists()
        assert not (tmp_path / "csv").exists()


class TestCli:
    def _args(self, tmp_path, source, extra=()):
        return [
            "--cli",
            "--source", str(source),
            "--output", str(tmp_path / "out"),
            "--csv-dir", str(tmp_path / "csv"),
            "--password", "pw",
            "--backup-dir", str(tmp_path / "backup"),
            "--report", str(tmp_path / "report.json"),
            *extra,
        ]

    def test_cli_writes_report_and_returns_zero(self, tmp_path):
        source = _make_source(tmp_path)
        code = main(self._args(tmp_path, source))
        assert code == 0
        data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
        assert data["success_count"] == 2
        assert (tmp_path / "out" / "patient").is_dir()
        assert (tmp_path / "out" / "control").is_dir()

    def test_cli_cases_subset(self, tmp_path):
        source = _make_source(tmp_path)
        code = main(self._args(tmp_path, source, ["--cases", f"control/{CONTROL}"]))
        assert code == 0
        data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
        assert [r["old_name"] for r in data["results"]] == [CONTROL]

    def test_cli_bad_cases_format_returns_two(self, tmp_path):
        source = _make_source(tmp_path)
        assert main(self._args(tmp_path, source, ["--cases", PATIENT])) == 2

    def test_cli_legacy_layout_returns_three(self, tmp_path):
        source = _make_source(tmp_path)
        (source / "0000000120260115093000").mkdir()
        assert main(self._args(tmp_path, source)) == 3
        data = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
        assert "layout_error" in data
        assert not (tmp_path / "out").exists()

    def test_cli_missing_args_returns_two(self):
        assert main(["--cli", "--source", "x"]) == 2
