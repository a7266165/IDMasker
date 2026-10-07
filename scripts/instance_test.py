"""
打包前後實例測試

在 workspace/<mode>/ 建立假資料（patient + control 案例、干擾夾、舊版 summary.csv、舊版備份），
以 --cli 跑完整流程，再比對輸出樹、CSV、備份與可解密性；第二次執行驗證全部跳過。
兩種模式都以 --gui-selftest 驗證 GUI 主視窗能建立；exe 模式另檢查打包進去的 Tcl/Tk DLL
來自建置環境（避免混到 base anaconda 的版本，見 IDMasker.spec 註解）。

用法（在 repo 根執行，用 idmasker conda env 的 python）:
    python scripts/instance_test.py --mode source
    python scripts/instance_test.py --mode exe [--exe dist/IDMasker.exe]

workspace/ 已 gitignore；每次執行會清掉 workspace/<mode>/ 重建。
備份一律指向 workspace 內，不會碰 paths.txt 的真實 BACKUP_DIR。
"""

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from src.crypto import derive_key  # noqa: E402
from src.csv_reporter import PROCESSED_HEADER, SUMMARY_HEADER  # noqa: E402
from src.folder_scanner import (  # noqa: E402
    PATTERN_ENCRYPTED_CONTROL,
    PATTERN_ENCRYPTED_PATIENT,
    decrypt_folder_name,
)

PASSWORD = "instance-test-pw"

# 假案例：資料夾名 -> 檔案清單（以 "_" 開頭者為 jpg，實際檔名 <資料夾名>_<編號>.jpg）
CASES = {
    # patient（22 碼）
    "0051014220260206082130": ["data.jsonl", "signal.edf", "_1.jpg", "_3.jpg", "notes.txt"],
    "0051014320260206091500": ["data.jsonl", "bio.acq", "_1.jpg"],
    "1234567820260301120000": ["data.jsonl", "signal.edf"],  # 無 jpg
    # control（10 碼身份證號 + 22 碼）；第一筆與 patient 第一筆同病歷號同時間，驗證分樹
    "A1234567890051014220260206082130": ["data.jsonl", "signal.edf", "_1.jpg", "_2.jpg", "notes.txt"],
    "B2876543219876543220260305143000": ["data.jsonl", "bio.acq", "_5.jpg"],
}
DECOYS = ["not_a_case", "12345", "20260206082130_AbCdEfGh1234"]

OLD_SUMMARY_HEADER = [
    "原始病例編號", "日期", "時分秒", "加密前檔名", "加密後檔名",
    "使用密碼", "JPG數量", "有JSON", "有EDF", "有ACQ", "加密時間",
]
OLD_SUMMARY_ROW = [
    '="00000001"', '="20260115"', '="093000"', '="0000000120260115093000"',
    "20260115093000_XyZwAbCd0001", PASSWORD, "3", "是", "否", "否", "2026-01-15 10:00:00",
]
OLD_BACKUPS = [
    "summary_20260101_000000.csv",            # 舊 summary 備份：應被刪
    "processed_20260101_000000.csv",          # 舊版命名（無來源夾名）：應被刪
    "processed_source_20260101_000000.csv",   # 同來源夾舊版：應被刪
    "processed_othersrc_20260101_000000.csv", # 其他來源夾：應保留
    "keep.txt",                               # 非備份檔：應保留
]


def _group(name: str) -> str:
    return "control" if len(name) == 32 else "patient"


def _national_id(name: str) -> str:
    return name[:10] if len(name) == 32 else ""


def _core(name: str) -> str:
    return name[-22:]


def _case_files(name: str) -> list[str]:
    return [f"{name}{f}" if f.startswith("_") else f for f in CASES[name]]


def _read_csv(path: Path) -> list[list[str]]:
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.reader(f))


class Checker:
    def __init__(self):
        self.items: list[tuple[str, bool, str]] = []

    def check(self, name: str, ok, detail: str = "") -> bool:
        self.items.append((name, bool(ok), detail))
        return bool(ok)

    @property
    def failures(self):
        return [i for i in self.items if not i[1]]


# ----- workspace -----

def build_workspace(ws: Path) -> dict[str, Path]:
    if ws.exists():
        shutil.rmtree(ws)
    dirs = {k: ws / k for k in ("source", "output", "csv", "backup")}
    for d in dirs.values():
        d.mkdir(parents=True)

    for name in CASES:
        folder = dirs["source"] / name
        folder.mkdir()
        for fname in _case_files(name):
            (folder / fname).write_bytes(f"{name}:{fname}".encode())
    for d in DECOYS:
        (dirs["source"] / d).mkdir()
    (dirs["source"] / "stray.txt").write_text("x")

    with open(dirs["csv"] / "summary.csv", "w", encoding="utf-8-sig", newline="") as f:
        csv.writer(f).writerows([OLD_SUMMARY_HEADER, OLD_SUMMARY_ROW])

    for n in OLD_BACKUPS:
        (dirs["backup"] / n).write_text("old")

    return dirs


def run_cli(prefix: list[str], dirs: dict[str, Path], report: Path) -> subprocess.CompletedProcess:
    cmd = prefix + [
        "--cli",
        "--source", str(dirs["source"]),
        "--output", str(dirs["output"]),
        "--csv-dir", str(dirs["csv"]),
        "--password", PASSWORD,
        "--backup-dir", str(dirs["backup"]),
        "--report", str(report),
    ]
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    return subprocess.run(
        cmd, cwd=REPO, env=env, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=600,
    )


# ----- 驗證 -----

def verify_first_run(c: Checker, dirs: dict[str, Path], report: Path, proc) -> None:
    c.check("第一次執行 exit code 0", proc.returncode == 0,
            f"rc={proc.returncode} out={proc.stdout!r} err={proc.stderr!r}")
    if not c.check("report.json 產生", report.exists()):
        return
    data = json.loads(report.read_text(encoding="utf-8"))
    c.check("report 計數 成功5/跳過0/失敗0",
            (data["success_count"], data["skipped_count"], data["fail_count"]) == (5, 0, 0),
            str({k: data[k] for k in ("success_count", "skipped_count", "fail_count")}))
    c.check("report 無備份錯誤", data["backup_error"] is None, str(data["backup_error"]))

    results = {r["old_name"]: r for r in data["results"]}
    c.check("掃描只收 5 個案例（干擾夾排除）", set(results) == set(CASES), str(sorted(results)))

    key = derive_key(PASSWORD)
    for name, r in results.items():
        new = r["new_name"] or ""
        detail = f"{name} -> {new}"
        is_control = _group(name) == "control"
        pattern = PATTERN_ENCRYPTED_CONTROL if is_control else PATTERN_ENCRYPTED_PATIENT
        expected_len = 29 if is_control else 27
        c.check(f"群組辨識 {name}", r["group"] == _group(name), detail)
        c.check(f"身份證號欄 {name}", r["national_id"] == _national_id(name), detail)
        c.check(f"加密名格式 {expected_len} 碼 {name}", pattern.fullmatch(new), detail)
        if is_control:
            nid = _national_id(name)
            c.check(f"身份證前 6 碼不外洩、末 4 碼原文 {name}",
                    nid[:6] not in new and new[-4:] == nid[6:], detail)
            c.check(f"病歷號不進名稱 {name}", _core(name)[:8] not in new, detail)
            expected_plain = nid + name[-14:]  # 身份證號 + 日期時間
        else:
            expected_plain = name
        try:
            c.check(f"可解密還原 {name}", decrypt_folder_name(new, key) == expected_plain, detail)
        except Exception as e:
            c.check(f"可解密還原 {name}", False, f"{detail}: {e}")

    # 同病歷號同時間的 patient / control：日期時間段相同，token 不同（病歷號 vs 身份證號）
    same = [n for n in CASES if _core(n) == "0051014220260206082130"]
    patient_new = next(results[n]["new_name"] for n in same if _group(n) == "patient")
    control_new = next(results[n]["new_name"] for n in same if _group(n) == "control")
    c.check("同核心 patient / control：同日期時間、不同 token",
            control_new[:15] == patient_new[:15] and control_new != patient_new,
            f"{control_new} vs {patient_new}")

    # 輸出樹
    out = dirs["output"]
    total_expected = 0
    for name, r in results.items():
        base = out / _group(name)
        new = r["new_name"]
        missing = []
        has_jpg = False
        for fname in _case_files(name):
            ext = Path(fname).suffix.lower()
            if ext in (".json", ".jsonl"):
                p = base / "radar" / f"{new}{ext}"
            elif ext in (".edf", ".acq"):
                p = base / "MP36" / f"{new}{ext}"
            elif ext in (".jpg", ".jpeg"):
                has_jpg = True
                seq = Path(fname).stem.rsplit("_", 1)[-1]
                p = base / "pic" / new / f"{new}_{seq}.jpg"
            else:
                p = base / "other" / new / fname
            total_expected += 1
            if not p.exists():
                missing.append(str(p.relative_to(out)))
        c.check(f"輸出檔案齊全 {name}", not missing, "缺: " + ", ".join(missing))
        if not has_jpg:
            c.check(f"無 jpg 不建 pic 子夾 {name}", not (base / "pic" / new).exists())

    for g in ("patient", "control"):
        c.check(f"{g}/ 四個子夾存在",
                all((out / g / s).is_dir() for s in ("radar", "MP36", "pic", "other")))

    all_paths = [str(p.relative_to(out)) for p in out.rglob("*")]
    files_only = [p for p in out.rglob("*") if p.is_file()]
    c.check("輸出檔案總數吻合", len(files_only) == total_expected,
            f"{len(files_only)} vs {total_expected}")
    leaks = [
        (ident, p) for p in all_paths
        for ident in [n[:10] for n in CASES if len(n) == 32]
        + [n[:6] for n in CASES if len(n) == 32]
        + [_core(n)[:8] for n in CASES]
        if ident in p
    ]
    c.check("輸出路徑無身份證號前 6 碼 / 完整病歷號", not leaks, str(leaks[:5]))

    # summary.csv
    rows = _read_csv(dirs["csv"] / "summary.csv")
    c.check("summary.csv 表頭升級", rows[0] == SUMMARY_HEADER, str(rows[0]))
    c.check("summary.csv 列數 表頭 + 1 舊 + 5 新 = 7", len(rows) == 7, str(len(rows)))
    c.check("summary.csv 舊列補 patient / 身份證號空",
            len(rows) > 1 and rows[1] == ["patient", ""] + OLD_SUMMARY_ROW, str(rows[1:2]))
    col = {h: i for i, h in enumerate(SUMMARY_HEADER)}
    for row in rows[2:]:
        old = row[col["加密前檔名"]].strip('="')
        r = results.get(old)
        ok = (
            r is not None
            and row[col["群組"]] == _group(old)
            and row[col["身份證號"]] == _national_id(old)
            and row[col["原始病例編號"]] == f'="{_core(old)[:8]}"'
            and row[col["加密後檔名"]] == r["new_name"]
            and row[col["使用密碼"]] == PASSWORD
            and row[col["JPG數量"]] == str(sum(1 for f in CASES[old] if f.startswith("_")))
        )
        c.check(f"summary.csv 新列正確 {old}", ok, str(row))
    c.check("summary.csv 無殘留 .tmp", not (dirs["csv"] / "summary.csv.tmp").exists())

    # processed.csv
    prow = _read_csv(dirs["source"] / "processed.csv")
    c.check("processed.csv 表頭", prow[0] == PROCESSED_HEADER, str(prow[0]))
    c.check("processed.csv 5 列", len(prow) == 6, str(len(prow)))

    # 備份
    names = sorted(p.name for p in dirs["backup"].iterdir())
    summaries = [n for n in names if n.startswith("summary_")]
    proc_src = [n for n in names if n.startswith("processed_source_")]
    c.check("備份只留一個 summary_*", len(summaries) == 1, str(names))
    c.check("備份只留一個 processed_source_*", len(proc_src) == 1, str(names))
    c.check("舊 summary 備份已刪", "summary_20260101_000000.csv" not in names, str(names))
    c.check("舊版命名 processed 備份已刪", "processed_20260101_000000.csv" not in names, str(names))
    c.check("其他來源夾備份保留", "processed_othersrc_20260101_000000.csv" in names, str(names))
    c.check("非備份檔保留", "keep.txt" in names, str(names))
    if summaries:
        c.check("summary 備份內容 == summary.csv",
                (dirs["backup"] / summaries[0]).read_bytes()
                == (dirs["csv"] / "summary.csv").read_bytes())


def verify_second_run(c: Checker, dirs: dict[str, Path], report: Path, proc, backup_before) -> None:
    c.check("第二次執行 exit code 0", proc.returncode == 0,
            f"rc={proc.returncode} out={proc.stdout!r} err={proc.stderr!r}")
    if not report.exists():
        c.check("第二次 report.json 產生", False)
        return
    data = json.loads(report.read_text(encoding="utf-8"))
    c.check("第二次 全部跳過 成功0/跳過5/失敗0",
            (data["success_count"], data["skipped_count"], data["fail_count"]) == (0, 5, 0),
            str({k: data[k] for k in ("success_count", "skipped_count", "fail_count")}))
    c.check("第二次 summary.csv 不增列", len(_read_csv(dirs["csv"] / "summary.csv")) == 7)
    c.check("第二次 備份夾不變",
            sorted(p.name for p in dirs["backup"].iterdir()) == backup_before)


def gui_selftest(c: Checker, prefix: list[str], ws: Path, mode: str) -> None:
    """用 --gui-selftest 建一次主視窗再關掉；只看行程存活會把錯誤對話框誤判成成功"""
    report = ws / "gui_selftest.json"
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    proc = subprocess.run(
        prefix + ["--gui-selftest", "--report", str(report)],
        cwd=REPO, env=env, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=120,
    )
    c.check("GUI selftest exit code 0", proc.returncode == 0,
            f"rc={proc.returncode} out={proc.stdout!r} err={proc.stderr!r}")
    if not report.exists():
        c.check("GUI selftest report 產生", False)
        return
    info = json.loads(report.read_text(encoding="utf-8"))
    c.check("GUI 主視窗可建立（tkinter / Tcl 可用）", info.get("ok"), (info.get("error") or "")[-600:])
    if info.get("ok"):
        c.check("GUI 視窗標題", info.get("title") == "IDMasker 去識別化工具", str(info.get("title")))
        print(f"[{mode}] Tcl patchlevel: {info.get('tcl_patchlevel')}  tcl_library: {info.get('tcl_library')}")


def check_bundled_tcl_dlls(c: Checker) -> None:
    """exe 模式：確認打包進去的 tcl86t.dll / tk86t.dll 來自建置用的 conda env，而非 base anaconda"""
    toc = REPO / "build" / "IDMasker" / "Analysis-00.toc"
    if not toc.exists():
        c.check("找到 build/IDMasker/Analysis-00.toc", False, str(toc))
        return
    text = toc.read_text(encoding="utf-8", errors="replace")
    env_root = Path(sys.executable).resolve().parent
    for dll in ("tcl86t.dll", "tk86t.dll"):
        m = re.search(rf"\('{dll}',\s*'([^']+)'", text)
        src = Path(m.group(1).replace("\\\\", "\\")).resolve() if m else None
        inside = src is not None and env_root in src.parents
        c.check(f"打包的 {dll} 來自建置環境", inside, f"{src} (env={env_root})")


# ----- 主程式 -----

def main() -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--mode", choices=["source", "exe"], required=True)
    ap.add_argument("--exe", default=str(REPO / "dist" / "IDMasker.exe"))
    ap.add_argument("--workspace", default=str(REPO / "workspace"))
    args = ap.parse_args()

    ws = Path(args.workspace) / args.mode
    dirs = build_workspace(ws)
    print(f"[{args.mode}] workspace: {ws}")

    if args.mode == "source":
        prefix = [sys.executable, "-m", "src.main"]
    else:
        exe = Path(args.exe)
        if not exe.exists():
            print(f"找不到 exe: {exe}")
            return 2
        prefix = [str(exe)]
    print(f"[{args.mode}] 執行: {' '.join(prefix)} --cli ...")

    c = Checker()
    p1 = run_cli(prefix, dirs, ws / "report1.json")
    verify_first_run(c, dirs, ws / "report1.json", p1)

    backup_before = sorted(p.name for p in dirs["backup"].iterdir())
    p2 = run_cli(prefix, dirs, ws / "report2.json")
    verify_second_run(c, dirs, ws / "report2.json", p2, backup_before)

    gui_selftest(c, prefix, ws, args.mode)
    if args.mode == "exe":
        check_bundled_tcl_dlls(c)

    lines = []
    for name, ok, detail in c.items:
        line = f"[{'PASS' if ok else 'FAIL'}] {name}"
        if not ok and detail:
            line += f"\n       {detail[:400]}"
        lines.append(line)
    passed = len(c.items) - len(c.failures)
    lines.append(f"\n{args.mode}: {passed}/{len(c.items)} 項通過")
    text = "\n".join(lines)
    print(text)
    (ws / "result.txt").write_text(text, encoding="utf-8")
    return 0 if not c.failures else 1


if __name__ == "__main__":
    sys.exit(main())
