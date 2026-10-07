"""
IDMasker 資料夾掃描、複製與重命名模組

負責掃描符合格式的子資料夾、辨識來源群組（patient / control）、
檢查檔案內容，以及執行加密複製。
"""

import os
import re
import shutil
from pathlib import Path

from src.crypto import (
    derive_key,
    encrypt_id,
    decrypt_id,
    encrypt_national_id,
    decrypt_national_id,
)

# patient 格式：22 碼純數字（前 8 碼病歷號 + 後 14 碼 YYYYMMDDHHMMSS）
PATTERN_PATIENT = re.compile(r"^\d{22}$")

# control 格式：10 碼身份證號（1 英文 + 1 英數 + 8 數字）+ 22 碼 patient 格式 = 32 碼
PATTERN_CONTROL = re.compile(r"^[A-Za-z][A-Za-z0-9]\d{8}\d{22}$")

# 加密格式（patient）：14 碼日期時間 + _ + 8 英文 + 4 數字（來自病歷號）= 27 碼
PATTERN_ENCRYPTED_PATIENT = re.compile(r"^\d{14}_[A-Za-z]{8}\d{4}$")

# 加密格式（control）：14 碼日期時間 + _ + 10 英文 + 4 數字（來自身份證號）= 29 碼
PATTERN_ENCRYPTED_CONTROL = re.compile(r"^\d{14}_[A-Za-z]{10}\d{4}$")

GROUP_PATIENT = "patient"
GROUP_CONTROL = "control"
GROUPS = (GROUP_PATIENT, GROUP_CONTROL)

NATIONAL_ID_LEN = 10
SUBDIRS = ("radar", "MP36", "pic", "other")


def classify_folder(folder_name: str) -> str | None:
    """判斷原始資料夾屬於哪個群組；格式不符回 None"""
    if PATTERN_PATIENT.match(folder_name):
        return GROUP_PATIENT
    if PATTERN_CONTROL.match(folder_name):
        return GROUP_CONTROL
    return None


def parse_folder_name(folder_name: str) -> dict:
    """
    拆解原始資料夾名稱

    Returns:
        dict 包含:
        - group: "patient" 或 "control"
        - national_id: 10 碼身份證號（patient 為空字串）
        - case_id: 8 碼病歷號
        - datetime_str: 14 碼 YYYYMMDDHHMMSS
        - core: 22 碼（case_id + datetime_str）
    """
    group = classify_folder(folder_name)
    if group is None:
        raise ValueError(f"資料夾名稱格式不符: {folder_name}")

    national_id = folder_name[:NATIONAL_ID_LEN] if group == GROUP_CONTROL else ""
    core = folder_name[len(national_id):]
    return {
        "group": group,
        "national_id": national_id,
        "case_id": core[:8],
        "datetime_str": core[8:],
        "core": core,
    }


def scan_for_encryption(parent_dir: str) -> list[str]:
    """
    掃描父資料夾中符合原始格式的子資料夾（patient 22 碼、control 32 碼皆收）

    Returns:
        符合格式的資料夾名稱列表（排序後）
    """
    parent = Path(parent_dir)
    if not parent.is_dir():
        raise FileNotFoundError(f"找不到資料夾: {parent_dir}")

    return sorted(
        entry.name
        for entry in parent.iterdir()
        if entry.is_dir() and classify_folder(entry.name) is not None
    )


def classify_encrypted(folder_name: str) -> str | None:
    """判斷加密資料夾名稱屬於哪個群組（由 token 長度區分）；格式不符回 None"""
    if PATTERN_ENCRYPTED_PATIENT.match(folder_name):
        return GROUP_PATIENT
    if PATTERN_ENCRYPTED_CONTROL.match(folder_name):
        return GROUP_CONTROL
    return None


def scan_for_decryption(parent_dir: str) -> list[str]:
    """
    掃描父資料夾中符合加密格式的子資料夾（patient 27 碼、control 29 碼皆收）

    Returns:
        符合格式的資料夾名稱列表（排序後）
    """
    parent = Path(parent_dir)
    if not parent.is_dir():
        raise FileNotFoundError(f"找不到資料夾: {parent_dir}")

    return sorted(
        entry.name
        for entry in parent.iterdir()
        if entry.is_dir() and classify_encrypted(entry.name) is not None
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

    patient: YYYYMMDDHHMMSS_<8英文4數字>    27 碼（token 由病歷號而來：前 4 碼加密、末 4 碼原文）
    control: YYYYMMDDHHMMSS_<10英文4數字>   29 碼（token 由身份證號而來：前 6 碼加密、末 4 碼原文）
    control 的病歷號不進入輸出名稱，只記錄在 summary.csv / processed.csv。

    Args:
        folder_name: 原始資料夾名稱（22 碼 patient 或 32 碼 control）
        key: 由 derive_key() 衍生的金鑰
    """
    parsed = parse_folder_name(folder_name)
    if parsed["group"] == GROUP_CONTROL:
        token = encrypt_national_id(parsed["national_id"], key)
    else:
        token = encrypt_id(parsed["case_id"], key)
    return parsed["datetime_str"] + "_" + token


def decrypt_folder_name(folder_name: str, key: bytes) -> str:
    """
    將加密資料夾名稱還原（群組由 token 長度判斷）

    patient 還原為 22 碼（病歷號 + 日期時間）。
    control 還原為 24 碼（身份證號 + 日期時間）；病歷號不在加密名稱內，需查 summary.csv。

    Args:
        folder_name: 加密資料夾名稱（27 碼 patient 或 29 碼 control）
        key: 由 derive_key() 衍生的金鑰
    """
    group = classify_encrypted(folder_name)
    if group is None:
        raise ValueError(f"資料夾名稱格式不符: {folder_name}")

    datetime_part = folder_name[:14]
    token = folder_name[15:]  # 跳過底線
    if group == GROUP_CONTROL:
        return decrypt_national_id(token, key) + datetime_part
    return decrypt_id(token, key) + datetime_part


def copy_and_encrypt_folders(
    source_dir: str,
    output_dir: str,
    folder_names: list[str],
    password: str,
) -> list[dict]:
    """
    批次複製並加密資料夾，依群組與檔案類型分流到子資料夾

    輸出結構（<group> 為 patient 或 control，只建立有處理到的群組）:
        output/<group>/radar/   .json / .jsonl（加密名稱.副檔名）
        output/<group>/MP36/    .edf / .acq（加密名稱.副檔名）
        output/<group>/pic/     .jpg / .jpeg（加密名稱/加密名稱_原編號.jpg）
        output/<group>/other/   其他檔案（加密名稱/原檔名）

    Args:
        source_dir: 來源父資料夾路徑
        output_dir: 輸出父資料夾路徑
        folder_names: 要處理的資料夾名稱列表
        password: 使用者密碼

    Returns:
        處理結果列表，每項包含:
        - old_name, new_name, success, skipped, error
        - group, national_id, case_id, datetime_str
        - file_info (jpg_count, has_json, has_edf, has_acq, other_count)
    """
    source = Path(source_dir)
    output = Path(output_dir)
    key = derive_key(password)
    prepared_groups: set[str] = set()
    results = []

    for name in folder_names:
        result = {
            "old_name": name,
            "new_name": None,
            "group": None,
            "national_id": "",
            "case_id": None,
            "datetime_str": None,
            "success": False,
            "skipped": False,
            "error": None,
            "file_info": None,
        }
        try:
            parsed = parse_folder_name(name)
            result.update(
                group=parsed["group"],
                national_id=parsed["national_id"],
                case_id=parsed["case_id"],
                datetime_str=parsed["datetime_str"],
            )
            new_name = encrypt_folder_name(name, key)
            src_path = source / name

            group_dir = output / parsed["group"]
            radar_dir, mp36_dir, pic_dir, other_dir = (group_dir / s for s in SUBDIRS)
            if parsed["group"] not in prepared_groups:
                for d in (radar_dir, mp36_dir, pic_dir, other_dir):
                    d.mkdir(parents=True, exist_ok=True)
                prepared_groups.add(parsed["group"])

            # 檢查是否已處理（該群組任一子資料夾下有此加密名稱）
            pic_case_dir = pic_dir / new_name
            already_processed = any(
                (d / new_name).exists()
                or list(d.glob(f"{new_name}.*"))
                for d in (radar_dir, mp36_dir, pic_dir, other_dir)
            )
            if already_processed:
                result["skipped"] = True
                result["new_name"] = new_name
                result["error"] = f"已處理過，跳過: {new_name}"
            else:
                # 檢查來源資料夾內的檔案
                result["file_info"] = inspect_folder_files(str(src_path))

                other_case_dir = other_dir / new_name

                # 遍歷所有檔案並分流
                for f in src_path.rglob("*"):
                    if not f.is_file():
                        continue
                    ext = f.suffix.lower()

                    if ext in (".json", ".jsonl"):
                        shutil.copy2(f, radar_dir / (new_name + ext))
                    elif ext in (".edf", ".acq"):
                        shutil.copy2(f, mp36_dir / (new_name + ext))
                    elif ext in (".jpg", ".jpeg"):
                        pic_case_dir.mkdir(parents=True, exist_ok=True)
                        # 取底線後的編號（如 00510142_3.jpg 取 3）
                        parts = f.stem.rsplit("_", 1)
                        seq = parts[-1] if len(parts) > 1 else f.stem
                        shutil.copy2(
                            f, pic_case_dir / f"{new_name}_{seq}.jpg"
                        )
                    else:
                        other_case_dir.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(f, other_case_dir / f.name)

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
