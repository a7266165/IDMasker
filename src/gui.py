"""
IDMasker GUI 模組

使用 tkinter 實作圖形介面。
"""

import csv
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
from pathlib import Path

from src.folder_scanner import scan_for_encryption, copy_and_encrypt_folders
from src.csv_reporter import generate_summary_csv, generate_processed_csv, backup_csvs, BACKUP_DIR


class IDMaskerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("IDMasker 去識別化工具")
        self.root.geometry("680x700")
        self.root.minsize(520, 600)
        self.root.resizable(True, True)

        self.scanned_folders: list[str] = []
        self.check_vars: list[tk.BooleanVar] = []

        self._build_ui()

    def _build_ui(self):
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        main = ttk.Frame(self.root, padding=16)
        main.grid(sticky="nsew")
        main.columnconfigure(0, weight=1)

        row = 0

        # --- 來源資料夾 ---
        ttk.Label(main, text="來源資料夾:").grid(row=row, column=0, sticky="w", pady=(0, 4))
        row += 1
        self.source_var = tk.StringVar()
        source_frame = ttk.Frame(main)
        source_frame.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        ttk.Entry(source_frame, textvariable=self.source_var, width=50).pack(side="left", fill="x", expand=True)
        ttk.Button(source_frame, text="瀏覽", command=self._browse_source).pack(side="left", padx=(4, 0))
        row += 1

        # --- 輸出資料夾 ---
        ttk.Label(main, text="輸出資料夾:").grid(row=row, column=0, sticky="w", pady=(0, 4))
        row += 1
        self.output_var = tk.StringVar()
        output_frame = ttk.Frame(main)
        output_frame.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        ttk.Entry(output_frame, textvariable=self.output_var, width=50).pack(side="left", fill="x", expand=True)
        ttk.Button(output_frame, text="瀏覽", command=self._browse_output).pack(side="left", padx=(4, 0))
        row += 1

        # --- CSV 資料夾 ---
        ttk.Label(main, text="Summary CSV 資料夾:").grid(row=row, column=0, sticky="w", pady=(0, 4))
        row += 1
        self.csv_var = tk.StringVar()
        csv_frame = ttk.Frame(main)
        csv_frame.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        ttk.Entry(csv_frame, textvariable=self.csv_var, width=50).pack(side="left", fill="x", expand=True)
        ttk.Button(csv_frame, text="瀏覽", command=self._browse_csv).pack(side="left", padx=(4, 0))
        row += 1

        # --- 密碼 ---
        ttk.Label(main, text="密碼:").grid(row=row, column=0, sticky="w", pady=(0, 4))
        row += 1
        self.pw_var = tk.StringVar()
        self.pw_entry = ttk.Entry(main, textvariable=self.pw_var, show="*", width=54)
        self.pw_entry.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        row += 1

        # --- 確認密碼 ---
        ttk.Label(main, text="確認密碼:").grid(row=row, column=0, sticky="w", pady=(0, 4))
        row += 1
        self.pw_confirm_var = tk.StringVar()
        self.pw_confirm_entry = ttk.Entry(main, textvariable=self.pw_confirm_var, show="*", width=54)
        self.pw_confirm_entry.grid(row=row, column=0, sticky="ew", pady=(0, 4))
        row += 1

        # --- 顯示密碼 ---
        self.show_pw_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            main, text="顯示密碼", variable=self.show_pw_var,
            command=self._toggle_password_visibility,
        ).grid(row=row, column=0, sticky="w", pady=(0, 12))
        row += 1

        # --- 掃描按鈕 ---
        ttk.Button(main, text="掃描資料夾", command=self._scan).grid(
            row=row, column=0, sticky="ew", pady=(0, 8)
        )
        row += 1

        # --- 掃描結果（勾選清單） ---
        ttk.Label(main, text="掃描結果:").grid(row=row, column=0, sticky="w", pady=(0, 4))
        row += 1

        list_frame = ttk.Frame(main)
        list_frame.grid(row=row, column=0, sticky="nsew", pady=(0, 8))
        main.rowconfigure(row, weight=1)

        self.canvas = tk.Canvas(list_frame, height=180, borderwidth=1, relief="sunken")
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.canvas.yview)
        self.checklist_frame = ttk.Frame(self.canvas)

        self.checklist_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")),
        )
        self.canvas.create_window((0, 0), window=self.checklist_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        row += 1

        # --- 全選 / 取消全選 ---
        select_frame = ttk.Frame(main)
        select_frame.grid(row=row, column=0, sticky="w", pady=(0, 8))
        ttk.Button(select_frame, text="全選", command=self._select_all).pack(side="left", padx=(0, 4))
        ttk.Button(select_frame, text="取消全選", command=self._deselect_all).pack(side="left")
        row += 1

        # --- 執行按鈕 ---
        self.run_btn = ttk.Button(main, text="執行加密", command=self._run_encrypt)
        self.run_btn.grid(row=row, column=0, sticky="ew", pady=(0, 8))
        row += 1

        # --- 狀態列 ---
        self.status_var = tk.StringVar(value="就緒")
        ttk.Label(main, textvariable=self.status_var, foreground="gray").grid(
            row=row, column=0, sticky="w"
        )

    # ----- 顯示密碼 -----

    def _toggle_password_visibility(self):
        show = "" if self.show_pw_var.get() else "*"
        self.pw_entry.configure(show=show)
        self.pw_confirm_entry.configure(show=show)

    # ----- 密碼一致性檢查 -----

    def _check_password_consistency(self, password: str) -> bool:
        """
        檢查密碼是否與現有 summary.csv 中的密碼一致。
        若不一致，彈出警告並詢問是否繼續。
        Returns True 表示可以繼續，False 表示取消。
        """
        csv_dir = self.csv_var.get().strip()
        if not csv_dir:
            return True
        csv_path = Path(csv_dir) / "summary.csv"
        if not csv_path.exists():
            return True

        try:
            with open(csv_path, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                existing_passwords = set()
                for row in reader:
                    pw = row.get("使用密碼", "").strip()
                    if pw:
                        existing_passwords.add(pw)

            if existing_passwords and password not in existing_passwords:
                return messagebox.askyesno(
                    "密碼不一致",
                    "目前輸入的密碼與 summary.csv 中記錄的密碼不同。\n"
                    "使用不同密碼將導致無法統一解密。\n\n"
                    "是否仍要繼續？",
                )
        except Exception:
            pass  # CSV 讀取失敗不阻擋主流程

        return True

    # ----- 瀏覽按鈕 -----

    def _browse_source(self):
        path = filedialog.askdirectory(title="選擇來源資料夾")
        if path:
            self.source_var.set(path)

    def _browse_output(self):
        path = filedialog.askdirectory(title="選擇輸出資料夾")
        if path:
            self.output_var.set(path)

    def _browse_csv(self):
        path = filedialog.askdirectory(title="選擇 Summary CSV 儲存資料夾")
        if path:
            self.csv_var.set(path)

    # ----- 掃描 -----

    def _scan(self):
        source = self.source_var.get().strip()
        if not source:
            messagebox.showwarning("警告", "請先選擇來源資料夾")
            return

        try:
            folders = scan_for_encryption(source)
        except FileNotFoundError as e:
            messagebox.showerror("錯誤", str(e))
            return

        # 清除舊的勾選清單
        for widget in self.checklist_frame.winfo_children():
            widget.destroy()

        self.scanned_folders = folders
        self.check_vars = []

        if not folders:
            ttk.Label(self.checklist_frame, text="（未找到符合格式的資料夾）").pack(anchor="w")
            self.status_var.set("掃描完成，無符合格式的資料夾")
            return

        for name in folders:
            var = tk.BooleanVar(value=True)
            self.check_vars.append(var)
            ttk.Checkbutton(self.checklist_frame, text=name, variable=var).pack(anchor="w")

        self.status_var.set(f"掃描完成，找到 {len(folders)} 個資料夾")

    def _select_all(self):
        for var in self.check_vars:
            var.set(True)

    def _deselect_all(self):
        for var in self.check_vars:
            var.set(False)

    # ----- 執行加密 -----

    def _validate_inputs(self) -> bool:
        if not self.source_var.get().strip():
            messagebox.showwarning("警告", "請選擇來源資料夾")
            return False
        if not self.output_var.get().strip():
            messagebox.showwarning("警告", "請選擇輸出資料夾")
            return False
        if not self.csv_var.get().strip():
            messagebox.showwarning("警告", "請選擇 Summary CSV 儲存資料夾")
            return False
        if not self.pw_var.get():
            messagebox.showwarning("警告", "請輸入密碼")
            return False
        if self.pw_var.get() != self.pw_confirm_var.get():
            messagebox.showerror("錯誤", "兩次密碼輸入不一致")
            return False

        selected = [
            self.scanned_folders[i]
            for i, var in enumerate(self.check_vars)
            if var.get()
        ]
        if not selected:
            messagebox.showwarning("警告", "請至少勾選一個資料夾")
            return False

        return True

    def _run_encrypt(self):
        if not self._validate_inputs():
            return

        if not self._check_password_consistency(self.pw_var.get()):
            return

        selected = [
            self.scanned_folders[i]
            for i, var in enumerate(self.check_vars)
            if var.get()
        ]
        source = self.source_var.get().strip()
        output = self.output_var.get().strip()
        csv_path = str(Path(self.csv_var.get().strip()) / "summary.csv")
        password = self.pw_var.get()

        self.run_btn.configure(state="disabled")
        self.status_var.set("加密中...")

        def worker():
            try:
                results = copy_and_encrypt_folders(source, output, selected, password)

                success_count = sum(1 for r in results if r["success"])
                skipped_count = sum(1 for r in results if r.get("skipped"))
                fail_count = len(results) - success_count - skipped_count

                # 只在有新成功結果時才產生/覆寫 CSV
                if success_count > 0:
                    generate_summary_csv(results, password, csv_path)

                    processed_path = generate_processed_csv(results, source)

                    # 備份兩份 CSV（失敗不中斷）
                    try:
                        backup_csvs(csv_path, processed_path)
                    except Exception:
                        pass  # 備份失敗不影響主流程

                # 回到主執行緒更新 UI
                self.root.after(0, lambda: self._on_complete(success_count, fail_count, results))
            except Exception:
                import traceback
                err_msg = traceback.format_exc()
                self.root.after(0, lambda msg=err_msg: self._on_error(msg))

        threading.Thread(target=worker, daemon=True).start()

    def _on_complete(self, success: int, fail: int, results: list[dict]):
        self.run_btn.configure(state="normal")

        skipped = [r for r in results if r.get("skipped")]
        errors = [r for r in results if not r["success"] and not r.get("skipped")]

        parts = [f"成功: {success}"]
        if skipped:
            parts.append(f"跳過: {len(skipped)}")
        if errors:
            parts.append(f"失敗: {len(errors)}")
        self.status_var.set("完成 — " + ", ".join(parts))

        msg = f"成功加密: {success} 個資料夾\n"

        if skipped:
            skipped_names = "\n".join(f"  {r['old_name']}" for r in skipped)
            msg += f"\n已處理過（跳過）: {len(skipped)} 個\n{skipped_names}\n"

        if errors:
            error_msgs = "\n".join(f"  {r['old_name']}: {r['error']}" for r in errors)
            msg += f"\n失敗: {len(errors)} 個\n{error_msgs}\n"

        if success > 0:
            msg += (
                f"\nsummary.csv 及 processed.csv 已儲存\n"
                f"備份已複製到:\n{BACKUP_DIR}"
            )

        if errors:
            messagebox.showwarning("完成（有警告）", msg)
        else:
            messagebox.showinfo("完成", msg)

    def _on_error(self, msg: str):
        self.run_btn.configure(state="normal")
        self.status_var.set("錯誤")
        messagebox.showerror("錯誤", msg)


def run_gui():
    root = tk.Tk()
    IDMaskerApp(root)
    root.mainloop()
