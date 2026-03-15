"""
IDMasker 資料夾掃描、複製與重命名模組

負責掃描符合格式的子資料夾，檢查檔案內容，以及執行加密複製。
"""

import os
import re
import shutil
from pathlib import Path

from src.crypto import derive_key, encrypt_id, decrypt_id

# 原始格式：20 碼純數字（前8碼ID + 後12碼日期時間）
PATTERN_ORIGINAL = re.compile(r"^\d{20}$")

# 加密格式：12碼數字 + _ + 8英文 + 4數字 = 25碼
PATTERN_ENCRYPTED = re.compile(r"^\d{12}_[A-Za-z]{8}\d{4}$")


def scan_for_encryption(parent_dir: str) -> list[str]:
    """
    掃描父資料夾中符合原始格式（20碼純數字）的子資料夾

    Returns:
        符合格式的資料夾名稱列表
    """
    parent = Path(parent_dir)
    if not parent.is_dir():
        raise FileNotFoundError(f"找不到資料夾: {parent_dir}")

    return sorted(
        entry.name
        for entry in parent.iterdir()
        if entry.is_dir() and PATTERN_ORIGINAL.match(entry.name)
    )


def scan_for_decryption(parent_dir: str) -> list[str]:
    """
    掃描父資料夾中符合加密格式（12碼+4英文+6數字）的子資料夾

    Returns:
        符合格式的資料夾名稱列表
    """
    parent = Path(parent_dir)
    if not parent.is_dir():
        raise FileNotFoundError(f"找不到資料夾: {parent_dir}")

    return sorted(
        entry.name
        for entry in parent.iterdir()
        if entry.is_dir() and PATTERN_ENCRYPTED.match(entry.name)
    )


def inspect_folder_files(folder_path: str) -> dict:
    """
    檢查資料夾內的檔案類型

    Returns:
        dict 包含 jpg_count, has_json, has_edf, has_acq, other_count
    """
    folder = Path(folder_path)
    jpg_count = 0
    has_json = False
    has_edf = False
    has_acq = False
    other_count = 0

    for f in folder.rglob("*"):
        if not f.is_file():
            continue
        ext = f.suffix.lower()
        if ext in (".jpg", ".jpeg"):
            jpg_count += 1
        elif ext in (".json", ".jsonl"):
            has_json = True
        elif ext == ".edf":
            has_edf = True
        elif ext == ".acq":
            has_acq = True
        else:
            other_count += 1

    return {
        "jpg_count": jpg_count,
        "has_json": has_json,
        "has_edf": has_edf,
        "has_acq": has_acq,
        "other_count": other_count,
    }


def encrypt_folder_name(folder_name: str, key: bytes) -> str:
    """
    將原始資料夾名稱轉換為加密名稱

    Args:
        folder_name: 原始資料夾名稱（20碼純數字）
        key: 由 derive_key() 衍生的金鑰

    Returns:
        加密後的資料夾名稱（25碼：YYYYMMDDHHMI_8英文4數字）
    """
    if not PATTERN_ORIGINAL.match(folder_name):
        raise ValueError(f"資料夾名稱格式不符: {folder_name}")

    eight_digits = folder_name[:8]
    datetime_part = folder_name[8:]
    encrypted = encrypt_id(eight_digits, key)

    return datetime_part + "_" + encrypted


def decrypt_folder_name(folder_name: str, key: bytes) -> str:
    """
    將加密資料夾名稱還原為原始名稱

    Args:
        folder_name: 加密資料夾名稱（25碼：YYYYMMDDHHMI_8英文4數字）
        key: 由 derive_key() 衍生的金鑰

    Returns:
        原始資料夾名稱（20碼純數字）
    """
    if not PATTERN_ENCRYPTED.match(folder_name):
        raise ValueError(f"資料夾名稱格式不符: {folder_name}")

    datetime_part = folder_name[:12]
    encrypted_part = folder_name[13:]  # 跳過底線
    eight_digits = decrypt_id(encrypted_part, key)

    return eight_digits + datetime_part


def copy_and_encrypt_folders(
    source_dir: str,
    output_dir: str,
    folder_names: list[str],
    password: str,
) -> list[dict]:
    """
    批次複製並加密資料夾，依檔案類型分流到子資料夾

    輸出結構:
        output/radar/   ← .jsonl 檔案
        output/MP36/    ← .edf / .acq 檔案
        output/pic/     ← .jpg/.jpeg 檔案（每個案一個加密名稱子資料夾，jpg 用流水號）
        output/other/   ← 其他檔案（每個案一個加密名稱子資料夾）

    Args:
        source_dir: 來源父資料夾路徑
        output_dir: 輸出父資料夾路徑
        folder_names: 要處理的資料夾名稱列表
        password: 使用者密碼

    Returns:
        處理結果列表，每項包含:
        - old_name, new_name, success, error
        - case_id, datetime_str (解析後的欄位)
        - file_info (jpg_count, has_json, has_edf, has_acq, other_count)
    """
    source = Path(source_dir)
    output = Path(output_dir)

    # 確保四個子資料夾存在
    radar_dir = output / "radar"
    mp36_dir = output / "MP36"
    pic_dir = output / "pic"
    other_dir = output / "other"
    for d in (radar_dir, mp36_dir, pic_dir, other_dir):
        d.mkdir(parents=True, exist_ok=True)

    key = derive_key(password)
    results = []

    for name in folder_names:
        result = {
            "old_name": name,
            "new_name": None,
            "case_id": name[:8],
            "datetime_str": name[8:],
            "success": False,
            "skipped": False,
            "error": None,
            "file_info": None,
        }
        try:
            new_name = encrypt_folder_name(name, key)
            src_path = source / name

            # 用 pic 子資料夾是否存在來判斷是否已處理
            pic_case_dir = pic_dir / new_name
            if pic_case_dir.exists():
                result["skipped"] = True
                result["new_name"] = new_name
                result["error"] = f"已處理過，跳過: {new_name}"
            else:
                # 檢查來源資料夾內的檔案
                result["file_info"] = inspect_folder_files(str(src_path))

                # 建立 pic 與 other 的個案子資料夾
                pic_case_dir.mkdir(parents=True, exist_ok=True)
                other_case_dir = other_dir / new_name

                # 遍歷所有檔案並分流
                jpg_counter = 0
                for f in src_path.rglob("*"):
                    if not f.is_file():
                        continue
                    ext = f.suffix.lower()

                    if ext in (".json", ".jsonl"):
                        shutil.copy2(f, radar_dir / (new_name + ext))
                    elif ext in (".edf", ".acq"):
                        shutil.copy2(f, mp36_dir / (new_name + ext))
                    elif ext in (".jpg", ".jpeg"):
                        jpg_counter += 1
                        shutil.copy2(f, pic_case_dir / f"{jpg_counter}.jpg")
                    else:
                        other_case_dir.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(f, other_case_dir / f.name)

                # 若 other 資料夾為空（沒有其他檔案），不保留空資料夾
                # （only created on demand above）

                result["new_name"] = new_name
                result["success"] = True
        except Exception as e:
            result["error"] = str(e)

        results.append(result)

    return results


def rename_folders(
    parent_dir: str,
    folder_names: list[str],
    password: str,
    mode: str,
) -> list[dict]:
    """
    批次原地重命名資料夾（用於解密還原）

    Args:
        parent_dir: 父資料夾路徑
        folder_names: 要處理的資料夾名稱列表
        password: 使用者密碼
        mode: "encrypt" 或 "decrypt"

    Returns:
        處理結果列表，每項包含 old_name, new_name, success, error
    """
    parent = Path(parent_dir)
    key = derive_key(password)
    transform = encrypt_folder_name if mode == "encrypt" else decrypt_folder_name
    results = []

    for name in folder_names:
        result = {"old_name": name, "new_name": None, "success": False, "error": None}
        try:
            new_name = transform(name, key)
            old_path = parent / name
            new_path = parent / new_name

            if new_path.exists():
                result["error"] = f"目標名稱已存在: {new_name}"
            else:
                os.rename(old_path, new_path)
                result["new_name"] = new_name
                result["success"] = True
        except Exception as e:
            result["error"] = str(e)

        results.append(result)

    return results
