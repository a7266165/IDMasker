"""
IDMasker CSV 報告產生模組

產生 summary.csv、processed.csv，並備份至 BACKUP_DIR（只保留最新一版）。
"""

import csv
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

_DEFAULT_BACKUP_DIR = Path.home() / "Documents" / "IDMasker" / "Backups"

SUMMARY_HEADER = [
    "群組",
    "身份證號",
    "原始病例編號",
    "日期",
    "時分秒",
    "加密前檔名",
    "加密後檔名",
    "使用密碼",
    "JPG數量",
    "有JSON",
    "有EDF",
    "有ACQ",
    "加密時間",
]

PROCESSED_HEADER = [
    "群組",
    "身份證號",
    "病例號碼",
    "日期",
    "時間",
    "資料夾名稱",
    "轉檔時間",
]

# 舊版 CSV 沒有群組 / 身份證號欄；當時只有 patient 一種來源，升級表頭時補上
_MIGRATE_DEFAULTS = {"群組": "patient"}

_TIMESTAMP_RE = r"\d{8}_\d{6}"


def _repo_root() -> Path:
    """repo 根（原始碼執行）或 exe 所在夾（PyInstaller 打包後）"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[1]


def _load_paths() -> dict:
    """讀 repo 根的 paths.txt（KEY=VALUE；已 gitignore，範本見 paths.example.txt）；缺檔回空 dict"""
    cfg: dict = {}
    p = _repo_root() / "paths.txt"
    if not p.exists():
        return cfg
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        cfg[k.strip()] = v.strip()
    return cfg


_PATHS = _load_paths()
# 備份夾：paths.txt 的 BACKUP_DIR；缺鍵退回 %USERPROFILE%\Documents\IDMasker\Backups
BACKUP_DIR = Path(_PATHS["BACKUP_DIR"]) if _PATHS.get("BACKUP_DIR") else _DEFAULT_BACKUP_DIR


def _excel_text(value: str) -> str:
    """包成 Excel 公式字串（`="..."`），避免開啟時被轉為數字/科學記號而掉前導 0"""
    return f'="{value}"'


def _append_rows(csv_path: str, header: list[str], rows: list[list]) -> None:
    """
    追加資料列；檔案不存在或為空則先寫表頭。

    若既有表頭與目前不同（舊版欄位），先讀出舊資料、依新表頭重寫
    （缺欄補 _MIGRATE_DEFAULTS 或空值）再追加，避免同一檔內欄數不一致。
    重寫經暫存檔後以 os.replace 原子取代。
    """
    path = Path(csv_path)
    old_header = None
    old_rows: list[dict] = []
    if path.exists() and path.stat().st_size > 0:
        with open(path, "r", newline="", encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            old_header = next(reader, None)
            if old_header is not None and old_header != header:
                old_rows = [dict(zip(old_header, r)) for r in reader]

    if old_header is None:
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(header)
            writer.writerows(rows)
        return

    if old_header == header:
        with open(path, "a", newline="", encoding="utf-8-sig") as f:
            csv.writer(f).writerows(rows)
        return

    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for d in old_rows:
            writer.writerow([d.get(col, _MIGRATE_DEFAULTS.get(col, "")) for col in header])
        writer.writerows(rows)
    os.replace(tmp, path)


def generate_summary_csv(results: list[dict], password: str, csv_path: str) -> None:
    """
    產生 summary.csv（加密總報告），追加寫入，不覆寫舊紀錄

    欄位見 SUMMARY_HEADER；舊版表頭會自動升級（見 _append_rows）。
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rows = []
    for r in results:
        if not r["success"]:
            continue

        file_info = r.get("file_info") or {}
        datetime_str = r["datetime_str"]  # YYYYMMDDHHMMSS
        rows.append([
            r["group"],
            r["national_id"],
            _excel_text(r["case_id"]),
            _excel_text(datetime_str[:8]),
            _excel_text(datetime_str[8:]),
            _excel_text(r["old_name"]),
            r["new_name"],
            password,
            file_info.get("jpg_count", 0),
            "是" if file_info.get("has_json") else "否",
            "是" if file_info.get("has_edf") else "否",
            "是" if file_info.get("has_acq") else "否",
            timestamp,
        ])

    _append_rows(csv_path, SUMMARY_HEADER, rows)


def generate_processed_csv(results: list[dict], source_dir: str) -> str:
    """
    產生 processed.csv（處理紀錄），輸出到來源資料夾，追加寫入

    欄位見 PROCESSED_HEADER；舊版表頭會自動升級（見 _append_rows）。

    Returns:
        processed.csv 的完整路徑
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    csv_path = str(Path(source_dir) / "processed.csv")
    rows = []
    for r in results:
        if not r["success"]:
            continue

        datetime_str = r["datetime_str"]  # YYYYMMDDHHMMSS
        rows.append([
            r["group"],
            r["national_id"],
            _excel_text(r["case_id"]),
            _excel_text(datetime_str[:8]),   # YYYYMMDD
            _excel_text(datetime_str[8:]),   # HHMMSS
            _excel_text(r["old_name"]),
            timestamp,
        ])

    _append_rows(csv_path, PROCESSED_HEADER, rows)
    return csv_path


def _prune_backups(backup_dir: Path, pattern: re.Pattern, keep: Path | None) -> list[Path]:
    """刪除 backup_dir 下檔名完全符合 pattern 的檔案（keep 除外），回傳刪除清單"""
    removed = []
    for p in backup_dir.iterdir():
        if p.is_file() and pattern.fullmatch(p.name) and (keep is None or p != keep):
            p.unlink()
            removed.append(p)
    return removed


def backup_csvs(
    summary_path: str,
    processed_path: str,
    backup_dir: str | Path | None = None,
) -> dict:
    """
    備份 summary.csv 與 processed.csv 到備份夾，只保留最新一版

    - summary 備份名 summary_<YYYYMMDD_HHMMSS>.csv；寫入後刪除其他 summary_<時間戳>.csv
    - processed 備份名 processed_<來源夾名>_<YYYYMMDD_HHMMSS>.csv；寫入後刪除同來源夾的
      其他版本，以及舊版沒有來源夾名的 processed_<時間戳>.csv
    summary.csv 為累積追加，最新一版即含全部紀錄；processed.csv 正本在各來源夾。

    Args:
        backup_dir: 預設 BACKUP_DIR（paths.txt 的 BACKUP_DIR，
                    缺鍵退回 %USERPROFILE%/Documents/IDMasker/Backups）

    Returns:
        dict: "summary" / "processed" 對應的備份檔路徑；來源不存在者不出現
    """
    target = Path(backup_dir) if backup_dir else BACKUP_DIR
    target.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    written: dict[str, Path] = {}

    summary_src = Path(summary_path)
    if summary_src.exists():
        dest = target / f"summary_{timestamp}.csv"
        shutil.copy2(summary_src, dest)
        _prune_backups(target, re.compile(rf"summary_{_TIMESTAMP_RE}\.csv"), keep=dest)
        written["summary"] = dest

    processed_src = Path(processed_path)
    if processed_src.exists():
        src_tag = processed_src.resolve().parent.name or "root"
        dest = target / f"processed_{src_tag}_{timestamp}.csv"
        shutil.copy2(processed_src, dest)
        _prune_backups(
            target,
            re.compile(rf"processed_{re.escape(src_tag)}_{_TIMESTAMP_RE}\.csv"),
            keep=dest,
        )
        # 舊版命名（無來源夾名）一併清掉
        _prune_backups(target, re.compile(rf"processed_{_TIMESTAMP_RE}\.csv"), keep=None)
        written["processed"] = dest

    return written
