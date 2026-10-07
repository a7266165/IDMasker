"""完整流程（pipeline）與 CLI 進入點測試"""

import csv
import json

from src.main import main
from src.pipeline import run_encryption
from src.csv_reporter import SUMMARY_HEADER

PATIENT = "1234567820260206082130"
CONTROL = "A123456789" + "8765432120260301120000"


def _make_source(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    for name in (PATIENT, CONTROL):
        folder = source / name
        folder.mkdir()
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
        assert {r["group"] for r in summary["results"]} == {"patient", "control"}

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

    def test_explicit_folder_subset(self, tmp_path):
        source = _make_source(tmp_path)
        summary = run_encryption(
            str(source), str(tmp_path / "out"), str(tmp_path / "csv"), "pw",
            folder_names=[CONTROL], backup_dir=tmp_path / "backup",
        )
        assert [r["old_name"] for r in summary["results"]] == [CONTROL]
        assert not (tmp_path / "out" / "patient").exists()


class TestCli:
    def test_cli_writes_report_and_returns_zero(self, tmp_path):
        source = _make_source(tmp_path)
        report = tmp_path / "report.json"
        code = main([
            "--cli",
            "--source", str(source),
            "--output", str(tmp_path / "out"),
            "--csv-dir", str(tmp_path / "csv"),
            "--password", "pw",
            "--backup-dir", str(tmp_path / "backup"),
            "--report", str(report),
        ])
        assert code == 0
        data = json.loads(report.read_text(encoding="utf-8"))
        assert data["success_count"] == 2
        assert len(data["results"]) == 2
        assert (tmp_path / "out" / "patient").is_dir()
        assert (tmp_path / "out" / "control").is_dir()

    def test_cli_missing_args_returns_two(self):
        assert main(["--cli", "--source", "x"]) == 2
