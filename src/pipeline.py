"""
IDMasker 加密流程

掃描、加密複製、summary / processed CSV、備份。GUI 與 CLI 共用同一條路徑。
"""

from pathlib import Path

from src.folder_scanner import scan_for_encryption, copy_and_encrypt_folders
from src.csv_reporter import generate_summary_csv, generate_processed_csv, backup_csvs


def run_encryption(
    source_dir: str,
    output_dir: str,
    csv_dir: str,
    password: str,
    folder_names: list[str] | None = None,
    backup_dir: str | Path | None = None,
) -> dict:
    """
    執行一次完整加密流程

    Args:
        source_dir: 來源父資料夾
        output_dir: 輸出父資料夾（底下自動分 patient / control）
        csv_dir: summary.csv 存放資料夾（不存在則建立）
        password: 加密密碼
        folder_names: 要處理的子資料夾；None 表示掃描 source_dir 下全部符合格式者
        backup_dir: 備份夾；None 用 csv_reporter.BACKUP_DIR

    Returns:
        dict:
        - results: copy_and_encrypt_folders 的逐筆結果
        - success_count / skipped_count / fail_count
        - summary_csv: summary.csv 路徑
        - processed_csv: processed.csv 路徑（無成功項目時為 None）
        - backup: {"summary": 路徑, "processed": 路徑}（未備份為空 dict）
        - backup_error: 備份失敗訊息（成功為 None）；備份失敗不中斷主流程
    """
    if folder_names is None:
        folder_names = scan_for_encryption(source_dir)

    Path(csv_dir).mkdir(parents=True, exist_ok=True)
    csv_path = str(Path(csv_dir) / "summary.csv")

    results = copy_and_encrypt_folders(source_dir, output_dir, folder_names, password)

    success_count = sum(1 for r in results if r["success"])
    skipped_count = sum(1 for r in results if r["skipped"])
    fail_count = len(results) - success_count - skipped_count

    processed_path = None
    backup: dict[str, str] = {}
    backup_error = None
    if success_count > 0:
        generate_summary_csv(results, password, csv_path)
        processed_path = generate_processed_csv(results, source_dir)
        try:
            written = backup_csvs(csv_path, processed_path, backup_dir=backup_dir)
            backup = {k: str(v) for k, v in written.items()}
        except Exception as e:  # 備份失敗不影響主流程
            backup_error = str(e)

    return {
        "results": results,
        "success_count": success_count,
        "skipped_count": skipped_count,
        "fail_count": fail_count,
        "summary_csv": csv_path,
        "processed_csv": processed_path,
        "backup": backup,
        "backup_error": backup_error,
    }
