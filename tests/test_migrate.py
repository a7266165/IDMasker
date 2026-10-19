"""舊版結構升級（一次性）測試"""

import csv
import json

from src.main import main
from src.migrate import plan_legacy_migration, apply_legacy_migration, format_actions
from src.csv_reporter import SUMMARY_HEADER, PROCESSED_HEADER
from src.folder_scanner import scan_for_encryption

CASE_A = "0051014220260206082130"
CASE_B = "0051014320260206091500"
ENC_A = "20260206082130_StrhjMQX0142"
ENC_B = "20260206091500_StrhjMQX0143"

OLD_SUMMARY_HEADER = [
    "原始病例編號", "日期", "時分秒", "加密前檔名", "加密後檔名",
    "使用密碼", "JPG數量", "有JSON", "有EDF", "有ACQ", "加密時間",
]
OLD_SUMMARY_ROW = ['="00510142"', '="20260206"', '="082130"', f'="{CASE_A}"', ENC_A,
                   "pw", "1", "是", "是", "否", "2026-02-06 09:00:00"]
OLD_PROCESSED_HEADER = ["病例號碼", "日期", "時間", "資料夾名稱", "轉檔時間"]
OLD_PROCESSED_ROW = ['="00510142"', '="20260206"', '="082130"', f'="{CASE_A}"', "2026-02-06 09:00:00"]


def _write_csv(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        csv.writer(f).writerows(rows)


def _read_csv(path):
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.reader(f))


def _make_legacy(tmp_path):
    """原始版擺法：來源頂層案例夾 + 舊 processed.csv；輸出頂層 radar/MP36/pic/other；舊 summary.csv"""
    source = tmp_path / "source"
    for name in (CASE_A, CASE_B):
        (source / name).mkdir(parents=True)
        (source / name / "data.jsonl").write_text("x")
        (source / name / f"{name}_1.jpg").write_bytes(b"jpg")
    _write_csv(source / "processed.csv", [OLD_PROCESSED_HEADER, OLD_PROCESSED_ROW])

    output = tmp_path / "output"
    (output / "radar").mkdir(parents=True)
    (output / "radar" / f"{ENC_A}.jsonl").write_text("r")
    (output / "MP36").mkdir()
    (output / "MP36" / f"{ENC_A}.edf").write_bytes(b"e")
    (output / "pic" / ENC_A).mkdir(parents=True)
    (output / "pic" / ENC_A / f"{ENC_A}_1.jpg").write_bytes(b"j")
    (output / "other" / ENC_A).mkdir(parents=True)
    (output / "other" / ENC_A / "notes.txt").write_text("n")

    csv_dir = tmp_path / "csv"
    _write_csv(csv_dir / "summary.csv", [OLD_SUMMARY_HEADER, OLD_SUMMARY_ROW])
    return source, output, csv_dir


class TestPlan:
    def test_plan_lists_everything_without_changing(self, tmp_path):
        source, output, csv_dir = _make_legacy(tmp_path)
        plan = plan_legacy_migration(str(source), str(output), str(csv_dir))

        kinds = sorted((a["kind"], a["label"]) for a in plan)
        assert kinds == sorted([
            ("move_case", CASE_A), ("move_case", CASE_B),
            ("move_dir", "radar"), ("move_dir", "MP36"), ("move_dir", "pic → tongue_image"), ("move_dir", "other"),
            ("upgrade_csv", "processed.csv"), ("upgrade_csv", "summary.csv"),
        ])
        assert all(a["status"] == "planned" for a in plan)
        # 只讀：什麼都沒動
        assert (source / CASE_A).is_dir() and not (source / "patient").exists()
        assert (output / "radar").is_dir() and not (output / "patient").exists()
        assert _read_csv(csv_dir / "summary.csv")[0] == OLD_SUMMARY_HEADER

    def test_plan_empty_when_already_new_layout(self, tmp_path):
        source = tmp_path / "source"
        (source / "patient" / CASE_A).mkdir(parents=True)
        _write_csv(source / "processed.csv", [PROCESSED_HEADER])
        output = tmp_path / "output"
        (output / "patient" / "radar").mkdir(parents=True)
        _write_csv(tmp_path / "csv" / "summary.csv", [SUMMARY_HEADER])
        assert plan_legacy_migration(str(source), str(output), str(tmp_path / "csv")) == []

    def test_plan_marks_conflicts(self, tmp_path):
        source, output, csv_dir = _make_legacy(tmp_path)
        (source / "patient" / CASE_A).mkdir(parents=True)  # 同名已存在
        (output / "patient" / "radar").mkdir(parents=True)
        (output / "patient" / "radar" / f"{ENC_A}.jsonl").write_text("existing")  # 同名檔已存在

        plan = plan_legacy_migration(str(source), str(output), str(csv_dir))
        by_label = {(a["kind"], a["label"]): a["status"] for a in plan}
        assert by_label[("move_case", CASE_A)] == "conflict"
        assert by_label[("move_case", CASE_B)] == "planned"
        assert by_label[("move_file", f"radar/{ENC_A}.jsonl")] == "conflict"  # radar 改為逐檔併入
        assert by_label[("move_dir", "MP36")] == "planned"


class TestApply:
    def test_apply_moves_and_upgrades(self, tmp_path):
        source, output, csv_dir = _make_legacy(tmp_path)
        results = apply_legacy_migration(plan_legacy_migration(str(source), str(output), str(csv_dir)))
        assert all(r["status"] == "done" for r in results)

        # 來源：案例進 patient/，頂層不再有案例夾，掃描可用
        assert (source / "patient" / CASE_A / "data.jsonl").exists()
        assert (source / "patient" / CASE_B / f"{CASE_B}_1.jpg").exists()
        assert not (source / CASE_A).exists()
        assert scan_for_encryption(str(source)) == [("patient", CASE_A), ("patient", CASE_B)]

        # 輸出：四個子夾整個搬進 patient/
        assert (output / "patient" / "radar" / f"{ENC_A}.jsonl").exists()
        assert (output / "patient" / "MP36" / f"{ENC_A}.edf").exists()
        assert (output / "patient" / "tongue_image" / ENC_A / f"{ENC_A}_1.jpg").exists()
        assert not (output / "patient" / "pic").exists()
        assert (output / "patient" / "other" / ENC_A / "notes.txt").exists()
        assert not any((output / s).exists() for s in ("radar", "MP36", "pic", "other"))

        # CSV 表頭升級，舊列群組補 patient
        assert _read_csv(source / "processed.csv") == [PROCESSED_HEADER, ["patient"] + OLD_PROCESSED_ROW]
        assert _read_csv(csv_dir / "summary.csv") == [SUMMARY_HEADER, ["patient"] + OLD_SUMMARY_ROW]

        # 再跑一次：沒東西可做
        assert plan_legacy_migration(str(source), str(output), str(csv_dir)) == []

    def test_apply_merges_files_and_keeps_conflicts(self, tmp_path):
        source, output, csv_dir = _make_legacy(tmp_path)
        (output / "patient" / "radar").mkdir(parents=True)
        (output / "patient" / "radar" / f"{ENC_A}.jsonl").write_text("existing")
        (output / "radar" / f"{ENC_B}.jsonl").write_text("new")

        results = apply_legacy_migration(plan_legacy_migration(str(source), str(output), str(csv_dir)))
        status = {(r["kind"], r["label"]): r["status"] for r in results}
        assert status[("move_file", f"radar/{ENC_A}.jsonl")] == "conflict"
        assert status[("move_file", f"radar/{ENC_B}.jsonl")] == "done"

        assert (output / "patient" / "radar" / f"{ENC_A}.jsonl").read_text() == "existing"  # 未覆寫
        assert (output / "patient" / "radar" / f"{ENC_B}.jsonl").read_text() == "new"
        assert (output / "radar" / f"{ENC_A}.jsonl").exists()  # 衝突檔留在原地
        assert not (output / "radar" / f"{ENC_B}.jsonl").exists()
        assert not (output / "MP36").exists()  # 其他子夾整個搬走

    def test_format_actions_mentions_counts(self, tmp_path):
        source, output, csv_dir = _make_legacy(tmp_path)
        text = format_actions(plan_legacy_migration(str(source), str(output), str(csv_dir)))
        assert "移動案例資料夾到 patient/：2 項" in text
        assert "移動輸出子夾到 patient/：4 項" in text
        assert "升級 CSV 表頭：2 項" in text
        assert format_actions([]) == "沒有需要升級的項目。"


class TestRenamePicToTongueImage:
    """改名前的中間版輸出（<group>/pic/）→ <group>/tongue_image/"""

    def _make_mid(self, tmp_path):
        source = tmp_path / "source"
        (source / "patient" / CASE_A).mkdir(parents=True)
        _write_csv(source / "processed.csv", [PROCESSED_HEADER])
        output = tmp_path / "output"
        for group in ("patient", "control"):
            (output / group / "radar").mkdir(parents=True)
            (output / group / "pic" / ENC_A).mkdir(parents=True)
            (output / group / "pic" / ENC_A / f"{ENC_A}_1.jpg").write_bytes(b"j")
        _write_csv(tmp_path / "csv" / "summary.csv", [SUMMARY_HEADER])
        return source, output, tmp_path / "csv"

    def test_plan_and_apply_rename(self, tmp_path):
        source, output, csv_dir = self._make_mid(tmp_path)
        plan = plan_legacy_migration(str(source), str(output), str(csv_dir))
        assert sorted((a["kind"], a["label"], a["status"]) for a in plan) == [
            ("rename_dir", "control/pic → tongue_image", "planned"),
            ("rename_dir", "patient/pic → tongue_image", "planned"),
        ]
        results = apply_legacy_migration(plan)
        assert all(r["status"] == "done" for r in results)
        for group in ("patient", "control"):
            assert (output / group / "tongue_image" / ENC_A / f"{ENC_A}_1.jpg").exists()
            assert not (output / group / "pic").exists()
        assert plan_legacy_migration(str(source), str(output), str(csv_dir)) == []

    def test_merge_into_existing_tongue_image(self, tmp_path):
        source, output, csv_dir = self._make_mid(tmp_path)
        (output / "patient" / "tongue_image" / ENC_A).mkdir(parents=True)
        (output / "patient" / "tongue_image" / ENC_A / f"{ENC_A}_1.jpg").write_bytes(b"existing")
        (output / "patient" / "pic" / ENC_B).mkdir()
        (output / "patient" / "pic" / ENC_B / f"{ENC_B}_1.jpg").write_bytes(b"new")

        results = apply_legacy_migration(plan_legacy_migration(str(source), str(output), str(csv_dir)))
        status = {(r["kind"], r["label"]): r["status"] for r in results}
        assert status[("move_file", f"patient/pic/{ENC_A}/{ENC_A}_1.jpg")] == "conflict"
        assert status[("move_file", f"patient/pic/{ENC_B}/{ENC_B}_1.jpg")] == "done"
        assert status[("rename_dir", "control/pic → tongue_image")] == "done"
        assert (output / "patient" / "tongue_image" / ENC_A / f"{ENC_A}_1.jpg").read_bytes() == b"existing"
        assert (output / "patient" / "tongue_image" / ENC_B / f"{ENC_B}_1.jpg").read_bytes() == b"new"
        assert (output / "patient" / "pic" / ENC_A / f"{ENC_A}_1.jpg").exists()  # 衝突檔留原地
        assert not (output / "patient" / "pic" / ENC_B).exists()  # 併入後空夾清掉


class TestCliMigrate:
    def test_dry_run_then_apply(self, tmp_path):
        source, output, csv_dir = _make_legacy(tmp_path)
        args = ["--migrate", "--source", str(source), "--output", str(output),
                "--csv-dir", str(csv_dir), "--report", str(tmp_path / "report.json")]

        assert main(args + ["--dry-run"]) == 0
        plan = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
        assert len(plan) == 8 and all(a["status"] == "planned" for a in plan)
        assert (source / CASE_A).is_dir()  # dry-run 沒動

        assert main(args) == 0
        results = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
        assert all(r["status"] == "done" for r in results)
        assert (source / "patient" / CASE_A).is_dir()

    def test_conflict_returns_one(self, tmp_path):
        source, output, csv_dir = _make_legacy(tmp_path)
        (source / "patient" / CASE_A).mkdir(parents=True)
        assert main(["--migrate", "--source", str(source), "--output", str(output),
                     "--csv-dir", str(csv_dir)]) == 1

    def test_missing_args_returns_two(self):
        assert main(["--migrate", "--source", "x"]) == 2
