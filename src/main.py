"""
IDMasker - 資料夾去識別化工具

程式進入點。無參數時開 GUI；加 --cli 走無介面模式（供自動化與打包後測試）；
加 --migrate 升級舊版資料夾結構（一次性）。
"""

import argparse
import json
import sys
from pathlib import Path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="IDMasker", description="資料夾去識別化工具")
    parser.add_argument("--cli", action="store_true", help="無介面模式：直接執行加密流程")
    parser.add_argument(
        "--migrate", action="store_true",
        help="升級舊版結構：來源夾頂層案例、輸出夾頂層 radar/MP36/pic/other 搬進 patient/，CSV 表頭升級",
    )
    parser.add_argument("--dry-run", action="store_true", help="與 --migrate 併用：只列計畫，不改任何東西")
    parser.add_argument("--source", help="來源資料夾（底下分 patient/ 與 control/）")
    parser.add_argument("--output", help="輸出資料夾（自動分 patient/ 與 control/）")
    parser.add_argument("--csv-dir", help="summary.csv 存放資料夾")
    parser.add_argument("--password", help="加密密碼（--cli 用）")
    parser.add_argument("--backup-dir", help="備份夾；省略時用 paths.txt 的 BACKUP_DIR")
    parser.add_argument(
        "--cases", nargs="*",
        help="只處理這些案例，格式 patient/<22碼> 或 control/<22碼>；省略時處理全部符合格式者",
    )
    parser.add_argument("--report", help="把執行結果寫成 JSON 到此路徑")
    parser.add_argument(
        "--gui-selftest",
        action="store_true",
        help="建立 GUI 主視窗後立即關閉，驗證 tkinter / Tcl 可用（打包後測試用）",
    )
    return parser


def _missing(args: argparse.Namespace, names: tuple[str, ...]) -> int | None:
    missing = [n for n in names if not getattr(args, n)]
    if missing:
        flags = ", ".join("--" + m.replace("_", "-") for m in missing)
        print(f"缺少參數: {flags}", file=sys.stderr)
        return 2
    return None


def _write_report(path: str | None, data) -> None:
    if path:
        Path(path).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _parse_cases(raw: list[str] | None) -> list[tuple[str, str]] | None:
    """'patient/0051014220260206082130' -> ('patient', '0051014220260206082130')"""
    if raw is None:
        return None
    from src.folder_scanner import GROUPS

    cases = []
    for item in raw:
        parts = item.replace("\\", "/").split("/", 1)
        if len(parts) != 2 or parts[0] not in GROUPS or not parts[1]:
            raise ValueError(f"--cases 格式錯誤: {item}（需 patient/<名稱> 或 control/<名稱>）")
        cases.append((parts[0], parts[1]))
    return cases


def run_cli(args: argparse.Namespace) -> int:
    """無介面加密；exit code：0 全部成功或跳過、1 有失敗、2 參數錯誤、3 來源夾結構不符"""
    if (code := _missing(args, ("source", "output", "csv_dir", "password"))) is not None:
        return code

    from src.folder_scanner import LayoutError
    from src.pipeline import run_encryption

    try:
        cases = _parse_cases(args.cases)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2

    try:
        summary = run_encryption(
            args.source,
            args.output,
            args.csv_dir,
            args.password,
            cases=cases,
            backup_dir=args.backup_dir,
        )
    except LayoutError as e:
        print(f"來源夾結構不符: {e}", file=sys.stderr)
        _write_report(args.report, {"layout_error": str(e)})
        return 3

    _write_report(args.report, summary)

    print(
        f"成功 {summary['success_count']}，跳過 {summary['skipped_count']}，"
        f"失敗 {summary['fail_count']}"
    )
    for r in summary["results"]:
        if not r["success"]:
            print(f"  [{r['group']}] {r['old_name']}: {r['error']}")
    if summary["backup_error"]:
        print(f"備份失敗: {summary['backup_error']}")

    return 0 if summary["fail_count"] == 0 else 1


def run_migrate(args: argparse.Namespace) -> int:
    """升級舊版結構；exit code：0 完成（或 dry-run）、1 有衝突或錯誤、2 參數不足"""
    if (code := _missing(args, ("source", "output", "csv_dir"))) is not None:
        return code

    from src.migrate import apply_legacy_migration, format_actions, plan_legacy_migration

    plan = plan_legacy_migration(args.source, args.output, args.csv_dir)
    if args.dry_run:
        print("[dry-run] 計畫如下，未改任何東西：")
        print(format_actions(plan))
        _write_report(args.report, plan)
        return 0

    results = apply_legacy_migration(plan)
    print(format_actions(results))
    _write_report(args.report, results)
    return 0 if all(r["status"] in ("done", "skipped") for r in results) else 1


def run_gui_selftest(report: str | None) -> int:
    """建一次 GUI 主視窗再關掉；回傳 0 成功、1 失敗。結果可寫 JSON 到 report"""
    import traceback

    info: dict = {"ok": False}
    try:
        import tkinter as tk
        from src.gui import IDMaskerApp

        root = tk.Tk()
        IDMaskerApp(root)
        root.update()
        # tk.call 可能回傳 Tcl_Obj 而非 str，先轉字串才能進 JSON
        info.update(
            ok=True,
            title=str(root.title()),
            tcl_patchlevel=str(root.tk.call("info", "patchlevel")),
            tcl_library=str(root.tk.call("set", "tcl_library")),
        )
        root.destroy()
    except Exception:
        info["error"] = traceback.format_exc()

    _write_report(report, info)
    print("GUI selftest:", "OK" if info["ok"] else "FAILED")
    if not info["ok"]:
        print(info["error"])
    return 0 if info["ok"] else 1


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.gui_selftest:
        return run_gui_selftest(args.report)
    if args.migrate:
        return run_migrate(args)
    if args.cli:
        return run_cli(args)

    from src.gui import run_gui

    run_gui()
    return 0


if __name__ == "__main__":
    sys.exit(main())
