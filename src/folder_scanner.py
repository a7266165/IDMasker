"""
IDMasker 資料夾掃描、複製與重命名模組

來源夾與輸出夾都分 patient/ 與 control/ 兩層，群組由案例所在的子資料夾決定；
兩群組的案例資料夾格式與加密規則完全相同。
"""

import os
import re
import shutil
from pathlib import Path

from src.crypto import derive_key, encrypt_id, decrypt_id

# 案例資料夾格式：22 碼純數字（前 8 碼病歷號 + 後 14 碼 YYYYMMDDHHMMSS）
PATTERN_CASE = re.compile(r"^\d{22}$")

# 加密格式：14 碼日期時間 + _ + 8 英文 + 4 數字 = 27 碼
PATTERN_ENCRYPTED = re.compile(r"^\d{14}_[A-Za-z]{8}\d{4}$")

GROUP_PATIENT = "patient"
GROUP_CONTROL = "control"
GROUPS = (GROUP_PATIENT, GROUP_CONTROL)

SUBDIRS = ("radar", "MP36", "pic", "other")


class LayoutError(ValueError):
    """來源夾結構不符新版（22 碼案例資料夾直接放在頂層，而非 patient/ 或 control/ 內）"""


def split_case_name(folder_name: str) -> tuple[str, str]:
    """22 碼案例名稱拆成 (8 碼病歷號, 14 碼日期時間)"""
    if not PATTERN_CASE.match(folder_name):
        raise ValueError(f"資料夾名稱格式不符: {folder_name}")
    return folder_name[:8], folder_name[8:]


def find_legacy_case_dirs(parent_dir: str) -> list[str]:
    """列出直接放在 parent_dir 頂層的 22 碼資料夾（舊版擺法）"""
    parent = Path(parent_dir)
    if not parent.is_dir():
        return []
    return sorted(
        entry.name
        for entry in parent.iterdir()
        if entry.is_dir() and PATTERN_CASE.match(entry.name)
    )


def scan_for_encryption(source_dir: str) -> list[tuple[str, str]]:
    """
    掃描來源夾底下 patient/ 與 control/ 內符合 22 碼格式的案例資料夾

    Returns:
        [(group, name), ...]，patient 在前，各群組內依名稱排序

    Raises:
        FileNotFoundError: 來源夾不存在
        LayoutError: 來源夾頂層直接放了 22 碼資料夾（舊版擺法），拒絕往下跑
    """
    source = Path(source_dir)
    if not source.is_dir():
        raise FileNotFoundError(f"找不到資料夾: {source_dir}")

    legacy = find_legacy_case_dirs(source_dir)
    if legacy:
        raise LayoutError(
            f"來源夾頂層直接放了 {len(legacy)} 個案例資料夾（例如 {legacy[0]}）。\n"
            "新版需放在 patient/ 或 control/ 子資料夾內；舊版資料請先執行「升級舊版結構」。"
        )

    cases: list[tuple[str, str]] = []
    for group in GROUPS:
        group_dir = source / group
        if not group_dir.is_dir():
            continue
        for entry in sorted(group_dir.iterdir(), key=lambda e: e.name):
            if entry.is_dir() and PATTERN_CASE.match(entry.name):
                cases.append((group, entry.name))
    return cases


def scan_for_decryption(parent_dir: str) -> list[str]:
    """
    掃描單一資料夾中符合加密格式（27 碼）的子資料夾

    Returns:
        符合格式的資料夾名稱列表（排序後）
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
    將 22 碼案例名稱轉換為加密名稱：YYYYMMDDHHMMSS_<8英文4數字>，27 碼

    Args:
        folder_name: 原始資料夾名稱（22 碼純數字）
        key: 由 derive_key() 衍生的金鑰
    """
    case_id, datetime_part = split_case_name(folder_name)
    return datetime_part + "_" + encrypt_id(case_id, key)


def decrypt_folder_name(folder_name: str, key: bytes) -> str:
    """
    將加密名稱還原為 22 碼案例名稱（病歷號 + 日期時間）

    Args:
        folder_name: 加密資料夾名稱（27 碼）
        key: 由 derive_key() 衍生的金鑰
    """
    if not PATTERN_ENCRYPTED.match(folder_name):
        raise ValueError(f"資料夾名稱格式不符: {folder_name}")

    datetime_part = folder_name[:14]
    encrypted_part = folder_name[15:]  # 跳過底線
    return decrypt_id(encrypted_part, key) + datetime_part


def copy_and_encrypt_folders(
    source_dir: str,
    output_dir: str,
    cases: list[tuple[str, str]],
    password: str,
) -> list[dict]:
    """
    批次複製並加密案例資料夾，依群組與檔案類型分流到子資料夾

    來源：source/<group>/<22碼案例>
    輸出（<group> 為 patient 或 control，只建立有處理到的群組）:
        output/<group>/radar/   .json / .jsonl（加密名稱.副檔名）
        output/<group>/MP36/    .edf / .acq（加密名稱.副檔名）
        output/<group>/pic/     .jpg / .jpeg（加密名稱/加密名稱_原編號.jpg）
        output/<group>/other/   其他檔案（加密名稱/原檔名）

    Args:
        source_dir: 來源父資料夾路徑
        output_dir: 輸出父資料夾路徑
        cases: [(group, name), ...]
        password: 使用者密碼

    Returns:
        處理結果列表，每項包含:
        - group, old_name, new_name, case_id, datetime_str
        - success, skipped, error
        - file_info (jpg_count, has_json, has_edf, has_acq, other_count)
    """
    source = Path(source_dir)
    output = Path(output_dir)
    key = derive_key(password)
    prepared_groups: set[str] = set()
    results = []

    for group, name in cases:
        result = {
            "group": group,
            "old_name": name,
            "new_name": None,
            "case_id": None,
            "datetime_str": None,
            "success": False,
            "skipped": False,
            "error": None,
            "file_info": None,
        }
        try:
            if group not in GROUPS:
                raise ValueError(f"未知群組: {group}")
            case_id, datetime_str = split_case_name(name)
            result.update(case_id=case_id, datetime_str=datetime_str)
            new_name = encrypt_folder_name(name, key)
            src_path = source / group / name
            if not src_path.is_dir():
                raise FileNotFoundError(f"找不到來源資料夾: {src_path}")

            group_dir = output / group
            radar_dir, mp36_dir, pic_dir, other_dir = (group_dir / s for s in SUBDIRS)
            if group not in prepared_groups:
                for d in (radar_dir, mp36_dir, pic_dir, other_dir):
                    d.mkdir(parents=True, exist_ok=True)
                prepared_groups.add(group)

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
    批次原地重命名單一資料夾內的子資料夾（用於解密還原）

    Args:
        parent_dir: 父資料夾路徑（例如 <來源夾>/patient）
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
