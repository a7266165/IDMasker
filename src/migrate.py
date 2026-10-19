"""
IDMasker 舊版結構升級（一次性）

原始版沒有 patient/control 分層，且只有 patient 一種來源，升級時全部歸入 patient/：
- 來源夾：頂層 22 碼案例資料夾 → patient/<同名>；processed.csv 表頭升級，舊列群組補 patient
- 輸出夾：頂層 radar/MP36/pic/other → patient/ 底下（目標已存在則逐檔併入）
- summary.csv：表頭升級，舊列群組補 patient

分「列計畫」（plan_legacy_migration，只讀）與「執行」（apply_legacy_migration）兩步。
同名目標一律不覆寫：列為 conflict，留在原地。
"""

import shutil
from collections import Counter
from pathlib import Path

from src.csv_reporter import PROCESSED_HEADER, SUMMARY_HEADER, _read_csv, upgrade_csv_header
from src.folder_scanner import GROUP_PATIENT, SUBDIRS, find_legacy_case_dirs

KIND_LABEL = {
    "move_case": "移動案例資料夾到 patient/",
    "move_dir": "移動輸出子夾到 patient/",
    "move_file": "併入輸出檔案到 patient/",
    "upgrade_csv": "升級 CSV 表頭",
}
STATUS_LABEL = {
    "planned": "待執行",
    "done": "完成",
    "conflict": "衝突，同名已存在，未動",
    "skipped": "略過",
    "error": "錯誤",
}


def _action(kind: str, src: Path, dst: Path, status: str, label: str, root: Path | None = None) -> dict:
    return {
        "kind": kind,
        "src": str(src),
        "dst": str(dst),
        "status": status,
        "label": label,
        "root": str(root) if root else None,
    }


def _needs_upgrade(path: Path, header: list[str]) -> bool:
    old_header, _ = _read_csv(path)
    return old_header is not None and old_header != header


def plan_legacy_migration(source_dir: str, output_dir: str, csv_dir: str) -> list[dict]:
    """
    列出升級要做的動作，不改任何東西

    Returns:
        [{kind, src, dst, status, label, root}, ...]
        kind: move_case / move_dir / move_file / upgrade_csv
        status: planned 或 conflict
    """
    actions: list[dict] = []
    source = Path(source_dir)
    output = Path(output_dir)

    if source.is_dir():
        for name in find_legacy_case_dirs(str(source)):
            dst = source / GROUP_PATIENT / name
            actions.append(_action(
                "move_case", source / name, dst,
                "conflict" if dst.exists() else "planned", name,
            ))
        processed = source / "processed.csv"
        if _needs_upgrade(processed, PROCESSED_HEADER):
            actions.append(_action("upgrade_csv", processed, processed, "planned", "processed.csv"))

    if output.is_dir():
        for sub in SUBDIRS:
            old = output / sub
            if not old.is_dir():
                continue
            new = output / GROUP_PATIENT / sub
            if not new.exists():
                actions.append(_action("move_dir", old, new, "planned", sub))
                continue
            for f in sorted(p for p in old.rglob("*") if p.is_file()):
                rel = f.relative_to(old)
                dst = new / rel
                actions.append(_action(
                    "move_file", f, dst,
                    "conflict" if dst.exists() else "planned",
                    f"{sub}/{rel.as_posix()}", root=old,
                ))

    summary = Path(csv_dir) / "summary.csv"
    if _needs_upgrade(summary, SUMMARY_HEADER):
        actions.append(_action("upgrade_csv", summary, summary, "planned", "summary.csv"))

    return actions


def _prune_empty_dirs(root: Path) -> None:
    """由下而上移除 root 內的空資料夾，最後 root 本身若空也移除"""
    if not root.is_dir():
        return
    for d in sorted((p for p in root.rglob("*") if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
        try:
            d.rmdir()
        except OSError:
            pass
    try:
        root.rmdir()
    except OSError:
        pass


def apply_legacy_migration(actions: list[dict]) -> list[dict]:
    """
    執行計畫中的動作；status 為 conflict 的不動

    Returns:
        帶最終 status 的動作清單（done / conflict / skipped / error；error 另有 error 欄）
    """
    results: list[dict] = []
    merged_roots: set[str] = set()

    for a in actions:
        r = dict(a)
        if a["status"] == "conflict":
            results.append(r)
            continue
        try:
            src, dst = Path(a["src"]), Path(a["dst"])
            if a["kind"] in ("move_case", "move_dir", "move_file"):
                if dst.exists():
                    r["status"] = "conflict"
                else:
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(src), str(dst))
                    r["status"] = "done"
                    if a["kind"] == "move_file" and a.get("root"):
                        merged_roots.add(a["root"])
            elif a["kind"] == "upgrade_csv":
                header = SUMMARY_HEADER if src.name == "summary.csv" else PROCESSED_HEADER
                r["status"] = "done" if upgrade_csv_header(str(src), header) else "skipped"
            else:
                r["status"] = "error"
                r["error"] = f"未知動作: {a['kind']}"
        except Exception as e:
            r["status"] = "error"
            r["error"] = str(e)
        results.append(r)

    for root in merged_roots:
        _prune_empty_dirs(Path(root))

    return results


def migrate_legacy_layout(source_dir: str, output_dir: str, csv_dir: str, dry_run: bool = False) -> list[dict]:
    """列計畫；dry_run 為 False 時接著執行。回傳動作清單"""
    actions = plan_legacy_migration(source_dir, output_dir, csv_dir)
    if dry_run:
        return actions
    return apply_legacy_migration(actions)


def format_actions(actions: list[dict], max_items: int = 8) -> str:
    """把動作清單整理成人看的多行文字（GUI 對話框與 CLI 共用）"""
    if not actions:
        return "沒有需要升級的項目。"
    lines: list[str] = []
    for kind, kind_label in KIND_LABEL.items():
        items = [a for a in actions if a["kind"] == kind]
        if not items:
            continue
        counts = Counter(a["status"] for a in items)
        count_txt = "、".join(f"{STATUS_LABEL[s]} {n}" for s, n in counts.items())
        lines.append(f"{kind_label}：{len(items)} 項（{count_txt}）")
        shown = items[:max_items]
        for a in shown:
            suffix = "" if a["status"] in ("planned", "done") else f"  [{STATUS_LABEL[a['status']]}]"
            if a["status"] == "error":
                suffix += f" {a.get('error', '')}"
            lines.append(f"    {a['label']}{suffix}")
        if len(items) > max_items:
            lines.append(f"    ... 另 {len(items) - max_items} 項")
    return "\n".join(lines)
