"""
IDMasker CSV 報告產生模組

產生 summary.csv、processed.csv，並備份至指定路徑。
"""

import csv
import shutil
from datetime import datetime
from pathlib import Path

BACKUP_DIR = Path.home() / "Documents" / "IDMasker" / "Backups"


def generate_summary_csv(results: list[dict], password: str, csv_path: str) -> None:
    """
    產生 summary.csv（加密總報告）

    若檔案已存在則追加新資料列，不覆寫舊紀錄。
    欄位: 原始病例編號、日期、時分、加密前檔名、加密後檔名、
          使用密碼、JPG數量、有JSON、有EDF、加密時間
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_exists = Path(csv_path).exists() and Path(csv_path).stat().st_size > 0

    with open(csv_path, "a", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)

        if not file_exists:
            writer.writerow([
                "原始病例編號",
                "日期",
                "時分",
                "加密前檔名",
                "加密後檔名",
                "使用密碼",
                "JPG數量",
                "有JSON",
                "有EDF",
                "加密時間",
            ])

        for r in results:
            if not r["success"]:
                continue

            file_info = r.get("file_info") or {}
            datetime_str = r["datetime_str"]  # YYYYMMDDHHMI
            writer.writerow([
                r["case_id"],
                datetime_str[:8],
                datetime_str[8:],
                r["old_name"],
                r["new_name"],
                password,
                file_info.get("jpg_count", 0),
                "是" if file_info.get("has_json") else "否",
                "是" if file_info.get("has_edf") else "否",
                timestamp,
            ])


def generate_processed_csv(results: list[dict], source_dir: str) -> str:
    """
    產生 processed.csv（處理紀錄），輸出到來源資料夾

    若檔案已存在則追加新資料列，不覆寫舊紀錄。
    欄位: 病例號碼、日期、時間、資料夾名稱、轉檔時間

    Returns:
        processed.csv 的完整路徑
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    csv_path = str(Path(source_dir) / "processed.csv")
    file_exists = Path(csv_path).exists() and Path(csv_path).stat().st_size > 0

    with open(csv_path, "a", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)

        if not file_exists:
            writer.writerow([
                "病例號碼",
                "日期",
                "時間",
                "資料夾名稱",
                "轉檔時間",
            ])

        for r in results:
            if not r["success"]:
                continue

            datetime_str = r["datetime_str"]  # YYYYMMDDHHMI
            date_part = datetime_str[:8]       # YYYYMMDD
            time_part = datetime_str[8:]       # HHMI

            writer.writerow([
                r["case_id"],
                date_part,
                time_part,
                r["old_name"],
                timestamp,
            ])

    return csv_path


def backup_csvs(summary_path: str, processed_path: str) -> None:
    """
    將 summary.csv 和 processed.csv 備份到固定備份目錄

    備份路徑: C:\\Users\\Administrator\\Documents\\IDMasker\\Backups
    """
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    summary_src = Path(summary_path)
    processed_src = Path(processed_path)

    if summary_src.exists():
        shutil.copy2(
            summary_src,
            BACKUP_DIR / f"summary_{timestamp}.csv",
        )

    if processed_src.exists():
        shutil.copy2(
            processed_src,
            BACKUP_DIR / f"processed_{timestamp}.csv",
        )
