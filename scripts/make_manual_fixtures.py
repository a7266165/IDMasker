"""
產生手動測試（GUI）用的假資料

workspace/manual_source/   5 個 patient + 5 個 control 案例資料夾（各含 jsonl、edf 或 acq、jpg、txt）
workspace/manual_output/   空的輸出測試夾；GUI 的「輸出資料夾」與「Summary CSV 資料夾」都可指到這裡

用法（在 repo 根執行）:
    python scripts/make_manual_fixtures.py          # 已存在時不動
    python scripts/make_manual_fixtures.py --force  # 清掉重建

注意：GUI 的備份會寫到 paths.txt 的真實 BACKUP_DIR，且只保留最新一版（會刪掉真實的舊備份）。
手動測試前請先把 paths.txt 的 BACKUP_DIR 暫時改到 workspace 內（例如 workspace/manual_backup），
測完改回；或改用 CLI 並指定 --backup-dir。
"""

import argparse
import json
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
WORKSPACE = REPO / "workspace"
SOURCE = WORKSPACE / "manual_source"
OUTPUT = WORKSPACE / "manual_output"

# (病歷號, 日期時間, jpg 數, 訊號檔副檔名, 是否有 notes.txt)
PATIENTS = [
    ("00510142", "20260206082130", 3, ".edf", True),
    ("00510143", "20260206091500", 2, ".acq", False),
    ("00523377", "20260212101045", 0, ".edf", True),   # 無 jpg
    ("01087265", "20260303140210", 1, ".edf", False),
    ("12345678", "20260318155900", 2, ".acq", True),
]

# (身份證號, 病歷號, 日期時間, jpg 數, 訊號檔副檔名, 是否有 notes.txt)
CONTROLS = [
    ("A123456789", "20000001", "20260405093015", 2, ".edf", True),
    ("B287654321", "20000002", "20260405104530", 3, ".acq", False),
    ("F131234567", "20000003", "20260410111200", 1, ".edf", True),
    ("H224567890", "20000004", "20260422133345", 0, ".acq", False),  # 無 jpg
    ("T198765432", "20000005", "20260501090000", 2, ".edf", True),
]


def _write_case(folder: Path, jpg_count: int, signal_ext: str, has_notes: bool) -> None:
    folder.mkdir(parents=True)
    name = folder.name

    with open(folder / "data.jsonl", "w", encoding="utf-8") as f:
        for i in range(5):
            f.write(json.dumps({"t": round(i * 0.5, 1), "range_m": 1.2 + i * 0.01, "case": name}) + "\n")

    (folder / f"signal{signal_ext}").write_bytes(b"PLACEHOLDER " * 64)

    for i in range(1, jpg_count + 1):
        (folder / f"{name}_{i}.jpg").write_bytes(b"\xff\xd8\xff\xe0JPEG-PLACEHOLDER" + bytes([i]) * 32 + b"\xff\xd9")

    if has_notes:
        (folder / "notes.txt").write_text(f"假資料 {name}\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--force", action="store_true", help="已存在時清掉重建")
    args = ap.parse_args()

    for d in (SOURCE, OUTPUT):
        if d.exists():
            if not args.force:
                print(f"已存在，略過（加 --force 重建）: {d}")
                continue
            shutil.rmtree(d)
        d.mkdir(parents=True)

    if not any(SOURCE.iterdir()):
        for case_id, dt, jpgs, ext, notes in PATIENTS:
            _write_case(SOURCE / f"{case_id}{dt}", jpgs, ext, notes)
        for nid, case_id, dt, jpgs, ext, notes in CONTROLS:
            _write_case(SOURCE / f"{nid}{case_id}{dt}", jpgs, ext, notes)
        print(f"來源假資料: {SOURCE}（patient {len(PATIENTS)}、control {len(CONTROLS)}）")

    print(f"輸出測試夾: {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
