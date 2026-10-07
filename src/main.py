"""
IDMasker - 資料夾去識別化工具

程式進入點。無參數時開 GUI；加 --cli 走無介面模式（供自動化與打包後測試）。
"""

import argparse
import json
import sys
from pathlib import Path


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="IDMasker", description="資料夾去識別化工具")
    parser.add_argument("--cli", action="store_true", help="無介面模式：直接執行加密流程")
    parser.add_argument("--source", help="來源資料夾")
    parser.add_argument("--output", help="輸出資料夾（自動分 patient / control）")
    parser.add_argument("--csv-dir", help="summary.csv 存放資料夾")
    parser.add_argument("--password", help="加密密碼")
    parser.add_argument("--backup-dir", help="備份夾；省略時用 paths.txt 的 BACKUP_DIR")
    parser.add_argument(
        "--folders", nargs="*", help="只處理這些子資料夾；省略時處理全部符合格式者"
    )
    parser.add_argument("--report", help="把執行結果寫成 JSON 到此路徑")
    parser.add_argument(
        "--gui-selftest",
        action="store_true",
        help="建立 GUI 主視窗後立即關閉，驗證 tkinter / Tcl 可用（打包後測試用）",
    )
    return parser


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

    if report:
        Path(report).write_text(json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")
    print("GUI selftest:", "OK" if info["ok"] else "FAILED")
    if not info["ok"]:
        print(info["error"])
    return 0 if info["ok"] else 1


def run_cli(args: argparse.Namespace) -> int:
    """無介面模式；回傳 exit code（0 全部成功或跳過，1 有失敗，2 參數不足）"""
    missing = [n for n in ("source", "output", "csv_dir", "password") if not getattr(args, n)]
    if missing:
        flags = ", ".join("--" + m.replace("_", "-") for m in missing)
        print(f"缺少參數: {flags}", file=sys.stderr)
        return 2

    from src.pipeline import run_encryption

    summary = run_encryption(
        args.source,
        args.output,
        args.csv_dir,
        args.password,
        folder_names=args.folders,
        backup_dir=args.backup_dir,
    )

    if args.report:
        Path(args.report).write_text(
            json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
        )

    print(
        f"成功 {summary['success_count']}，跳過 {summary['skipped_count']}，"
        f"失敗 {summary['fail_count']}"
    )
    for r in summary["results"]:
        if not r["success"]:
            print(f"  {r['old_name']}: {r['error']}")
    if summary["backup_error"]:
        print(f"備份失敗: {summary['backup_error']}")

    return 0 if summary["fail_count"] == 0 else 1


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.gui_selftest:
        return run_gui_selftest(args.report)
    if args.cli:
        return run_cli(args)

    from src.gui import run_gui

    run_gui()
    return 0


if __name__ == "__main__":
    sys.exit(main())
