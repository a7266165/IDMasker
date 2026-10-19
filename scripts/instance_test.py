"""
打包前後實例測試

在 workspace/<mode>/ 建立假資料（patient/ 與 control/ 各數個案例、干擾夾、舊版 summary.csv、舊版備份），
以 --cli 跑完整流程，再比對輸出樹、CSV、備份與可解密性；第二次執行驗證全部跳過。
另外驗證：來源夾頂層直接放 22 碼資料夾時直接報錯；--migrate 能把舊版結構升級成新版並接著正常加密。
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
from src.folder_scanner import PATTERN_ENCRYPTED, SUBDIRS, decrypt_folder_name, encrypt_folder_name  # noqa: E402

PASSWORD = "instance-test-pw"

# group -> {22 碼案例名: 檔案清單}（以 "_" 開頭者為 jpg，實際檔名 <案例名>_<編號>.jpg）
CASES = {
    "patient": {
        "0051014220260206082130": ["data.jsonl", "signal.edf", "_1.jpg", "_3.jpg", "notes.txt"],
        "0051014320260206091500": ["data.jsonl", "bio.acq", "_1.jpg"],
        "1234567820260301120000": ["data.jsonl", "signal.edf"],  # 無 jpg
    },
    "control": {
        "0051014220260206082130": ["data.jsonl", "signal.edf", "_1.jpg", "_2.jpg", "notes.txt"],  # 與 patient 同名，驗證分樹
        "2000000220260305143000": ["data.jsonl", "bio.acq", "_5.jpg"],
    },
}
ALL_CASES = [(g, n) for g in CASES for n in CASES[g]]
DECOYS = ["not_a_case", "12345", "20260206082130_AbCdEfGh1234"]  # 非 22 碼：頂層與群組夾內都應忽略

OLD_SUMMARY_HEADER = [
    "原始病例編號", "日期", "時分秒", "加密前檔名", "加密後檔名",
    "使用密碼", "JPG數量", "有JSON", "有EDF", "有ACQ", "加密時間",
]
OLD_SUMMARY_ROW = [
    '="00000001"', '="20260115"', '="093000"', '="0000000120260115093000"',
    "20260115093000_XyZwAbCd0001", PASSWORD, "3", "是", "否", "否", "2026-01-15 10:00:00",
]
OLD_PROCESSED_HEADER = ["病例號碼", "日期", "時間", "資料夾名稱", "轉檔時間"]
OLD_PROCESSED_ROW = ['="00000001"', '="20260115"', '="093000"', '="0000000120260115093000"', "2026-01-15 10:00:00"]
OLD_BACKUPS = [
    "summary_20260101_000000.csv",            # 舊 summary 備份：應被刪
    "processed_20260101_000000.csv",          # 舊版命名（無來源夾名）：應被刪
    "processed_source_20260101_000000.csv",   # 同來源夾舊版：應被刪
    "processed_othersrc_20260101_000000.csv", # 其他來源夾：應保留
    "keep.txt",                               # 非備份檔：應保留
]


def _case_files(group: str, name: str) -> list[str]:
    return [f"{name}{f}" if f.startswith("_") else f for f in CASES[group][name]]


def _read_csv(path: Path) -> list[list[str]]:
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.reader(f))


def _write_csv(path: Path, rows) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        csv.writer(f).writerows(rows)


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

def _make_case_dir(folder: Path, files: list[str]) -> None:
    folder.mkdir(parents=True)
    for fname in files:
        (folder / fname).write_bytes(f"{folder.name}:{fname}".encode())


def build_workspace(ws: Path) -> dict[str, Path]:
    if ws.exists():
        shutil.rmtree(ws)
    dirs = {k: ws / k for k in ("source", "output", "csv", "backup")}
    for d in dirs.values():
        d.mkdir(parents=True)

    for group, name in ALL_CASES:
        _make_case_dir(dirs["source"] / group / name, _case_files(group, name))
    for d in DECOYS:
        (dirs["source"] / d).mkdir()
        (dirs["source"] / "patient" / d).mkdir()
    (dirs["source"] / "stray.txt").write_text("x")

    _write_csv(dirs["csv"] / "summary.csv", [OLD_SUMMARY_HEADER, OLD_SUMMARY_ROW])

    for n in OLD_BACKUPS:
        (dirs["backup"] / n).write_text("old")

    return dirs


def _run(prefix: list[str], args: list[str]) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    return subprocess.run(
        prefix + args, cwd=REPO, env=env, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=600,
    )


def run_cli(prefix: list[str], source: Path, output: Path, csv_dir: Path, backup: Path, report: Path):
    return _run(prefix, [
        "--cli",
        "--source", str(source),
        "--output", str(output),
        "--csv-dir", str(csv_dir),
        "--password", PASSWORD,
        "--backup-dir", str(backup),
        "--report", str(report),
    ])


def _rc_detail(proc) -> str:
    return f"rc={proc.returncode} out={proc.stdout!r} err={proc.stderr!r}"


# ----- 驗證：主流程 -----

def verify_first_run(c: Checker, dirs: dict[str, Path], report: Path, proc) -> None:
    c.check("第一次執行 exit code 0", proc.returncode == 0, _rc_detail(proc))
    if not c.check("report.json 產生", report.exists()):
        return
    data = json.loads(report.read_text(encoding="utf-8"))
    n = len(ALL_CASES)
    c.check(f"report 計數 成功{n}/跳過0/失敗0",
            (data["success_count"], data["skipped_count"], data["fail_count"]) == (n, 0, 0),
            str({k: data[k] for k in ("success_count", "skipped_count", "fail_count")}))
    c.check("report 無備份錯誤", data["backup_error"] is None, str(data["backup_error"]))

    results = {(r["group"], r["old_name"]): r for r in data["results"]}
    c.check("掃描只收 patient/ 與 control/ 內的案例（干擾夾排除）",
            set(results) == set(ALL_CASES), str(sorted(results)))

    key = derive_key(PASSWORD)
    for (group, name), r in results.items():
        new = r["new_name"] or ""
        detail = f"[{group}] {name} -> {new}"
        c.check(f"群組 {group} {name}", r["group"] == group, detail)
        c.check(f"加密名 27 碼格式 {group} {name}", PATTERN_ENCRYPTED.fullmatch(new), detail)
        c.check(f"加密名與程式庫一致 {group} {name}", new == encrypt_folder_name(name, key), detail)
        try:
            c.check(f"可解密還原 {group} {name}", decrypt_folder_name(new, key) == name, detail)
        except Exception as e:
            c.check(f"可解密還原 {group} {name}", False, f"{detail}: {e}")

    same = "0051014220260206082130"
    c.check("同名案例在 patient/ 與 control/：加密名相同",
            results[("patient", same)]["new_name"] == results[("control", same)]["new_name"])

    # 輸出樹
    out = dirs["output"]
    total_expected = 0
    for (group, name), r in results.items():
        base = out / group
        new = r["new_name"]
        missing = []
        has_jpg = False
        for fname in _case_files(group, name):
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
        c.check(f"輸出檔案齊全 {group} {name}", not missing, "缺: " + ", ".join(missing))
        if not has_jpg:
            c.check(f"無 jpg 不建 pic 子夾 {group} {name}", not (base / "pic" / new).exists())

    for g in ("patient", "control"):
        c.check(f"{g}/ 四個子夾存在", all((out / g / s).is_dir() for s in SUBDIRS))
    c.check("輸出夾頂層沒有 radar/MP36/pic/other", not any((out / s).exists() for s in SUBDIRS))

    all_paths = [str(p.relative_to(out)) for p in out.rglob("*")]
    files_only = [p for p in out.rglob("*") if p.is_file()]
    c.check("輸出檔案總數吻合", len(files_only) == total_expected, f"{len(files_only)} vs {total_expected}")
    case_ids = {n[:8] for _, n in ALL_CASES}
    leaks = [(cid, p) for p in all_paths for cid in case_ids if cid in p]
    c.check("輸出路徑無完整病歷號", not leaks, str(leaks[:5]))

    # summary.csv
    rows = _read_csv(dirs["csv"] / "summary.csv")
    c.check("summary.csv 表頭升級", rows[0] == SUMMARY_HEADER, str(rows[0]))
    c.check(f"summary.csv 列數 表頭 + 1 舊 + {n} 新", len(rows) == 2 + n, str(len(rows)))
    c.check("summary.csv 舊列補 patient", len(rows) > 1 and rows[1] == ["patient"] + OLD_SUMMARY_ROW, str(rows[1:2]))
    col = {h: i for i, h in enumerate(SUMMARY_HEADER)}
    for row in rows[2:]:
        old = row[col["加密前檔名"]].strip('="')
        group = row[col["群組"]]
        r = results.get((group, old))
        ok = (
            r is not None
            and row[col["原始病例編號"]] == f'="{old[:8]}"'
            and row[col["加密後檔名"]] == r["new_name"]
            and row[col["使用密碼"]] == PASSWORD
            and row[col["JPG數量"]] == str(sum(1 for f in CASES[group][old] if f.startswith("_")))
        )
        c.check(f"summary.csv 新列正確 {group} {old}", ok, str(row))
    c.check("summary.csv 無殘留 .tmp", not (dirs["csv"] / "summary.csv.tmp").exists())

    # processed.csv（來源夾頂層一份）
    prow = _read_csv(dirs["source"] / "processed.csv")
    c.check("processed.csv 表頭", prow[0] == PROCESSED_HEADER, str(prow[0]))
    c.check(f"processed.csv {n} 列", len(prow) == 1 + n, str(len(prow)))
    c.check("processed.csv 群組欄正確",
            sorted(r[0] for r in prow[1:]) == sorted(g for g, _ in ALL_CASES))

    # 備份
    names = sorted(p.name for p in dirs["backup"].iterdir())
    summaries = [x for x in names if x.startswith("summary_")]
    proc_src = [x for x in names if x.startswith("processed_source_")]
    c.check("備份只留一個 summary_*", len(summaries) == 1, str(names))
    c.check("備份只留一個 processed_source_*", len(proc_src) == 1, str(names))
    c.check("舊 summary 備份已刪", "summary_20260101_000000.csv" not in names, str(names))
    c.check("舊版命名 processed 備份已刪", "processed_20260101_000000.csv" not in names, str(names))
    c.check("其他來源夾備份保留", "processed_othersrc_20260101_000000.csv" in names, str(names))
    c.check("非備份檔保留", "keep.txt" in names, str(names))
    if summaries:
        c.check("summary 備份內容 == summary.csv",
                (dirs["backup"] / summaries[0]).read_bytes() == (dirs["csv"] / "summary.csv").read_bytes())


def verify_second_run(c: Checker, dirs: dict[str, Path], report: Path, proc, backup_before) -> None:
    c.check("第二次執行 exit code 0", proc.returncode == 0, _rc_detail(proc))
    if not report.exists():
        c.check("第二次 report.json 產生", False)
        return
    data = json.loads(report.read_text(encoding="utf-8"))
    n = len(ALL_CASES)
    c.check(f"第二次 全部跳過 成功0/跳過{n}/失敗0",
            (data["success_count"], data["skipped_count"], data["fail_count"]) == (0, n, 0),
            str({k: data[k] for k in ("success_count", "skipped_count", "fail_count")}))
    c.check("第二次 summary.csv 不增列", len(_read_csv(dirs["csv"] / "summary.csv")) == 2 + n)
    c.check("第二次 備份夾不變", sorted(p.name for p in dirs["backup"].iterdir()) == backup_before)


# ----- 驗證：頂層放案例夾要報錯 -----

def verify_layout_error(c: Checker, prefix: list[str], ws: Path) -> None:
    base = ws / "layout_error"
    source = base / "source"
    _make_case_dir(source / "patient" / "0051014220260206082130", ["data.jsonl"])
    _make_case_dir(source / "0000000120260115093000", ["data.jsonl"])  # 頂層 22 碼：舊版擺法
    output, csv_dir, backup, report = base / "output", base / "csv", base / "backup", base / "report.json"

    proc = run_cli(prefix, source, output, csv_dir, backup, report)
    c.check("頂層放案例夾：exit code 3", proc.returncode == 3, _rc_detail(proc))
    c.check("頂層放案例夾：不建立輸出夾 / CSV 夾 / 備份夾",
            not output.exists() and not csv_dir.exists() and not backup.exists())
    c.check("頂層放案例夾：report 記錄 layout_error",
            report.exists() and "layout_error" in json.loads(report.read_text(encoding="utf-8")))


# ----- 驗證：舊版結構升級 -----

LEGACY_CASES = ["0051014220260206082130", "0051014320260206091500"]
LEGACY_ENC = "20260101000000_AbCdEfGh0001"  # 舊輸出裡的（假）加密名


def verify_migration(c: Checker, prefix: list[str], ws: Path) -> None:
    base = ws / "legacy"
    source, output, csv_dir, backup = base / "source", base / "output", base / "csv", base / "backup"
    for name in LEGACY_CASES:
        _make_case_dir(source / name, ["data.jsonl", f"{name}_1.jpg"])
    _write_csv(source / "processed.csv", [OLD_PROCESSED_HEADER, OLD_PROCESSED_ROW])
    (output / "radar").mkdir(parents=True)
    (output / "radar" / f"{LEGACY_ENC}.jsonl").write_text("r")
    (output / "MP36").mkdir()
    (output / "MP36" / f"{LEGACY_ENC}.edf").write_bytes(b"e")
    (output / "pic" / LEGACY_ENC).mkdir(parents=True)
    (output / "pic" / LEGACY_ENC / f"{LEGACY_ENC}_1.jpg").write_bytes(b"j")
    (output / "other" / LEGACY_ENC).mkdir(parents=True)
    (output / "other" / LEGACY_ENC / "notes.txt").write_text("n")
    _write_csv(csv_dir / "summary.csv", [OLD_SUMMARY_HEADER, OLD_SUMMARY_ROW])

    migrate_args = ["--migrate", "--source", str(source), "--output", str(output), "--csv-dir", str(csv_dir)]

    # dry-run：只列計畫
    r1 = base / "plan.json"
    proc = _run(prefix, migrate_args + ["--dry-run", "--report", str(r1)])
    c.check("migrate dry-run exit code 0", proc.returncode == 0, _rc_detail(proc))
    plan = json.loads(r1.read_text(encoding="utf-8")) if r1.exists() else []
    c.check("migrate dry-run 計畫 8 項皆 planned",
            len(plan) == 8 and all(a["status"] == "planned" for a in plan), str([(a["kind"], a["label"], a["status"]) for a in plan]))
    c.check("migrate dry-run 沒動檔案",
            all((source / n).is_dir() for n in LEGACY_CASES) and (output / "radar").is_dir()
            and not (source / "patient").exists() and not (output / "patient").exists())

    # 實際執行
    r2 = base / "migrate.json"
    proc = _run(prefix, migrate_args + ["--report", str(r2)])
    c.check("migrate exit code 0", proc.returncode == 0, _rc_detail(proc))
    done = json.loads(r2.read_text(encoding="utf-8")) if r2.exists() else []
    c.check("migrate 全部 done", len(done) == 8 and all(a["status"] == "done" for a in done),
            str([(a["kind"], a["label"], a["status"]) for a in done]))
    c.check("migrate 來源案例進 patient/",
            all((source / "patient" / n / "data.jsonl").exists() for n in LEGACY_CASES)
            and not any((source / n).exists() for n in LEGACY_CASES))
    c.check("migrate 輸出子夾進 patient/",
            (output / "patient" / "radar" / f"{LEGACY_ENC}.jsonl").exists()
            and (output / "patient" / "pic" / LEGACY_ENC / f"{LEGACY_ENC}_1.jpg").exists()
            and (output / "patient" / "other" / LEGACY_ENC / "notes.txt").exists()
            and not any((output / s).exists() for s in SUBDIRS))
    c.check("migrate processed.csv 升級",
            _read_csv(source / "processed.csv") == [PROCESSED_HEADER, ["patient"] + OLD_PROCESSED_ROW])
    c.check("migrate summary.csv 升級",
            _read_csv(csv_dir / "summary.csv") == [SUMMARY_HEADER, ["patient"] + OLD_SUMMARY_ROW])

    # 升級後直接加密：舊案例應能正常處理
    r3 = base / "encrypt.json"
    proc = run_cli(prefix, source, output, csv_dir, backup, r3)
    c.check("migrate 後加密 exit code 0", proc.returncode == 0, _rc_detail(proc))
    data = json.loads(r3.read_text(encoding="utf-8")) if r3.exists() else {}
    c.check("migrate 後加密 成功2/跳過0/失敗0",
            (data.get("success_count"), data.get("skipped_count"), data.get("fail_count")) == (2, 0, 0), str(data.get("results")))
    c.check("migrate 後 summary.csv = 表頭 + 1 舊 + 2 新", len(_read_csv(csv_dir / "summary.csv")) == 4)


# ----- GUI / 打包 -----

def gui_selftest(c: Checker, prefix: list[str], ws: Path, mode: str) -> None:
    """用 --gui-selftest 建一次主視窗再關掉；只看行程存活會把錯誤對話框誤判成成功"""
    report = ws / "gui_selftest.json"
    proc = _run(prefix, ["--gui-selftest", "--report", str(report)])
    c.check("GUI selftest exit code 0", proc.returncode == 0, _rc_detail(proc))
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
    p1 = run_cli(prefix, dirs["source"], dirs["output"], dirs["csv"], dirs["backup"], ws / "report1.json")
    verify_first_run(c, dirs, ws / "report1.json", p1)

    backup_before = sorted(p.name for p in dirs["backup"].iterdir())
    p2 = run_cli(prefix, dirs["source"], dirs["output"], dirs["csv"], dirs["backup"], ws / "report2.json")
    verify_second_run(c, dirs, ws / "report2.json", p2, backup_before)

    verify_layout_error(c, prefix, ws)
    verify_migration(c, prefix, ws)

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
