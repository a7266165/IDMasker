# IDMasker - 資料夾去識別化工具 需求規格書

本文件描述程式**目前的實際行為**。格式演進見 git log。

## 1. 概述

將含有可識別病歷號的案例資料夾，透過 FPE（Format-Preserving Encryption）概念的加密，
複製成去識別化名稱的輸出。原始資料夾保留不動；檔案內容不做改動，只改名稱與擺放位置。

加密為確定性：同密碼 + 同病歷號永遠得到同一結果；持有密碼者可還原病歷號。

來源分兩個群組 **patient** 與 **control**，由案例所在的子資料夾決定；
兩群組的案例資料夾格式與加密規則完全相同。

## 2. 資料夾結構

### 2.1 輸入（來源夾）
```
<來源夾>/
├── patient/
│   ├── XXXXXXXXYYYYMMDDHHMMSS/      22 碼：8 碼病歷號 + 14 碼日期時間
│   │   ├── *.jsonl / *.json
│   │   ├── *.edf / *.acq
│   │   ├── <案例名>_<編號>.jpg
│   │   └── 其他檔案
│   └── ...
├── control/
│   └── XXXXXXXXYYYYMMDDHHMMSS/      同 patient 格式
└── processed.csv                    執行後產生（來源夾頂層一份，含「群組」欄）
```
- 群組夾可以只有其中一個
- 群組夾內非 22 碼純數字的資料夾一律忽略
- **來源夾頂層若直接放了 22 碼資料夾（舊版擺法），掃描直接報錯，不往下跑**；舊版資料請先執行「升級舊版結構」（第 7 節）

### 2.2 輸出（輸出夾）
```
<輸出夾>/
├── patient/
│   ├── radar/   <加密名>.jsonl 或 .json
│   ├── MP36/    <加密名>.edf 或 .acq
│   ├── pic/     <加密名>/<加密名>_<原編號>.jpg
│   └── other/   <加密名>/<原檔名>
└── control/
    └── （結構同上）
```
- 只建立有處理到的群組；每個群組的四個子資料夾一律建立
- pic 檔名的「原編號」取自來源 jpg 檔名最後一個底線後的字串（`..._3.jpg` 取 `3`），無底線時用整個檔名主幹
- 「已處理」判斷：該群組四個子資料夾中任一存在 `<加密名>` 或 `<加密名>.*`
- 同名案例同時在 patient/ 與 control/：加密名相同，但分屬不同群組樹，互不影響

## 3. 名稱轉換

### 3.1 加密後名稱（兩群組相同）
```
YYYYMMDDHHMMSS_LLLLLLLLDDDD      共 27 碼
```
- 日期時間移到前方，底線分隔
- `LLLLLLLL`：8 個英文字母（大小寫混合），由病歷號**前 4 碼**加密而來
- `DDDD`：病歷號**末 4 碼，保留明文**

### 3.2 範例（字母部分為示意）
```
加密前  1234567820260206082130   ->  20260206082130_xKpRmNvB5678
還原    20260206082130_xKpRmNvB5678   ->  1234567820260206082130
```

## 4. 操作流程

### 4.1 GUI
1. 選擇來源資料夾、輸出資料夾、summary.csv 存放資料夾
2. 輸入密碼兩次（可勾「顯示密碼」）
3. 「掃描資料夾」：列出 patient/ 與 control/ 內符合格式的案例，清單前綴 `[patient]` / `[control]`，預設全勾；狀態列顯示各群組數量。來源夾頂層放了案例夾時跳錯誤視窗
4. 「執行加密」：
   - 若 summary.csv 已存在且密碼與既有紀錄不同，跳出警告並詢問是否繼續
   - 逐一加密、複製到輸出目錄（第 2.2 節）
   - 該群組已有同名結果者跳過
   - 寫入 summary.csv、processed.csv，並備份（第 6 節）
5. 顯示成功（含各群組數）/ 跳過 / 失敗數與明細
6. 「升級舊版結構」按鈕：見第 7 節

### 4.2 無介面模式（CLI）
GUI 與 CLI 共用 `src/pipeline.py` 的 `run_encryption`，流程完全相同。CLI 供自動化與打包後測試：
```
IDMasker.exe --cli --source <來源夾> --output <輸出夾> --csv-dir <summary.csv 夾> --password <密碼>
             [--backup-dir <備份夾>] [--cases patient/<22碼> control/<22碼> ...] [--report <結果.json>]
```
- `--backup-dir` 省略時用 `paths.txt` 的 `BACKUP_DIR`；`--cases` 省略時處理全部符合格式者
- `--report` 把逐筆結果與計數寫成 JSON（windowed exe 沒有 console，靠這個拿結果）
- exit code：0 全部成功或跳過、1 有失敗、2 參數錯誤、3 來源夾結構不符
- `--gui-selftest [--report <json>]`：建一次主視窗再關掉，回報 Tcl 版本與 tcl_library；
  exit 0 成功、1 失敗。用來驗證打包後 tkinter 可用（只看行程存活會把錯誤對話框誤判成成功）

## 5. 加密方案

### 5.1 金鑰衍生
PBKDF2-HMAC-SHA256，固定 salt `IDMasker_v1_salt`，100,000 次迭代，256-bit key。
固定 salt 是刻意的：確保同密碼 + 同輸入 = 同輸出。

### 5.2 病歷號加密（`encrypt_id`）
1. 取前 4 碼為整數 n（0~9999）
2. 8 輪 Feistel 網絡（左右各 0~99，輪函數 HMAC-SHA256），得 m（0~9999），一對一映射
3. 以 HMAC-SHA256(key, `"letters:"` + m) 前 8 bytes 各 mod 52 映射至 `A-Za-z`，得 8 個字母
4. 輸出 = 8 字母 + 原末 4 碼

### 5.3 解密（`decrypt_id`）
窮舉 m 於 0~9999 比對 8 字母，再做 Feistel 逆運算。密碼錯誤時找不到匹配，拋出 `ValueError`。

### 5.4 安全特性與限制
- 無密碼無法還原前 4 碼；同密碼同輸入結果固定；一對一映射無碰撞
- 病歷號末 4 碼明文外露，是刻意取捨
- summary.csv 含原始病歷號與**明文密碼**，是再識別鑰匙；其存放夾與備份夾不入 git、不進雲端同步

## 6. CSV 報告與備份

### 6.1 summary.csv
路徑：使用者指定的資料夾 / `summary.csv`，追加寫入，不覆寫舊紀錄。

| 欄位 | 說明 |
|---|---|
| 群組 | patient / control |
| 原始病例編號 | 8 碼病歷號 |
| 日期 | YYYYMMDD |
| 時分秒 | HHMMSS |
| 加密前檔名 | 原始 22 碼資料夾名稱 |
| 加密後檔名 | 27 碼加密名稱 |
| 使用密碼 | 明文 |
| JPG數量 | .jpg / .jpeg 數 |
| 有JSON / 有EDF / 有ACQ | 是 / 否 |
| 加密時間 | 執行時間 |

數字類欄位以 `="..."` 包裝，避免 Excel 掉前導 0。

### 6.2 processed.csv
路徑：來源夾頂層 / `processed.csv`，追加寫入。
欄位：群組、病例號碼、日期、時間、資料夾名稱、轉檔時間。

### 6.3 表頭升級
既有 CSV 表頭若為舊版（無「群組」欄），下次寫入時自動重寫為新表頭：
舊資料列群組補 `patient`，其餘欄位依欄名對應，多餘欄位丟棄。重寫經暫存檔後原子取代，不會留下半截檔案。
也可用第 7 節的升級功能主動一次做完。

### 6.4 備份
- 備份夾：`paths.txt` 的 `BACKUP_DIR`（範本 `paths.example.txt`）；缺檔或缺鍵時用 `%USERPROFILE%\Documents\IDMasker\Backups`
- 每次加密完成後自動備份，**只保留最新一版**：
  - `summary_<YYYYMMDD_HHMMSS>.csv`：寫入後刪除其他 `summary_<時間戳>.csv`
  - `processed_<來源夾名>_<YYYYMMDD_HHMMSS>.csv`：寫入後刪除**同來源夾**的其他版本，以及舊版沒有來源夾名的 `processed_<時間戳>.csv`；其他來源夾的備份不動
- summary.csv 為累積追加，最新一版備份即含全部歷史；processed.csv 正本在來源夾
- 備份失敗不中斷主流程

## 7. 舊版結構升級（一次性）

原始版沒有 patient/control 分層，且只有 patient 一種來源，升級時全部歸入 patient/：

| 對象 | 動作 |
|---|---|
| 來源夾頂層 22 碼案例資料夾 | 搬到 `patient/<同名>` |
| 來源夾 processed.csv | 表頭升級，舊列群組補 patient |
| 輸出夾頂層 radar / MP36 / pic / other | 搬到 `patient/` 底下；目標已存在則逐檔併入 |
| summary.csv | 表頭升級，舊列群組補 patient |

- 分「列計畫」與「執行」兩步：GUI 按鈕先彈出計畫清單，按「是」才執行；CLI 用 `--dry-run` 只列計畫
- 同名目標一律不覆寫：列為「衝突」留在原地，其餘照做
- 升級後舊輸出仍在，重新掃描加密會判定「已處理」跳過
```
IDMasker.exe --migrate --source <來源夾> --output <輸出夾> --csv-dir <summary.csv 夾> [--dry-run] [--report <json>]
```
exit code：0 完成（或 dry-run）、1 有衝突或錯誤、2 參數不足

## 8. 解密 / 還原

程式庫層提供（`src/folder_scanner.py`）：
- `scan_for_decryption(dir)`：列出單一資料夾內 27 碼加密格式的子資料夾
- `rename_folders(dir, names, password, mode="decrypt")`：原地改回 22 碼名稱（例如對 `<來源夾>/patient` 操作）

**目前 GUI 沒有解密入口**，上述功能只能在 Python 中呼叫。加密名稱本身看不出群組，群組由所在的 patient/ 或 control/ 子夾決定。

## 9. 技術規格

- Python 3.10+；相依 `pycryptodome`；GUI 用內建 tkinter
- 以 PyInstaller 打包（`IDMasker.spec`，windowed 單一 exe）；打包後 `paths.txt` 讀 exe 所在夾
- **Tcl/Tk 版本陷阱（conda）**：PyInstaller 依 PATH 搜 `tcl86t.dll` / `tk86t.dll`。若 PATH 先碰到
  base anaconda 的 `Library\bin`（8.6.15），會和 idmasker env 的 Tcl 腳本（`init.tcl` 要求
  `-exact 8.6.13`）混包，exe 開 GUI 時報 `version conflict for package "Tcl"`，CLI 不受影響。
  `IDMasker.spec` 已強制從 `sys.prefix\Library\bin` 取 DLL 並插到 PATH 最前；
  `scripts/instance_test.py --mode exe` 會檢查打包來源與 GUI selftest
- 開發執行：`run.bat`（conda env `idmasker`）
- 單元測試：`python -m pytest tests/`
- 實例測試（打包前後）：`python scripts/instance_test.py --mode source` 與 `--mode exe`。
  在 `workspace/<mode>/` 建假資料（patient/ 與 control/ 案例、干擾夾、舊版 summary.csv、舊版備份），
  以 `--cli` 跑完整流程並驗證輸出樹、CSV 升級、備份清理、可解密性、重跑全跳過、
  頂層放案例夾要報錯、`--migrate` 升級後能正常加密；exe 模式另測 GUI 能啟動與 Tcl/Tk DLL 來源。
  備份一律指向 workspace 內，不碰真實 `BACKUP_DIR`。

### 專案結構
```
IDMasker/
├── docs/SPEC.md              # 本文件
├── src/
│   ├── main.py               # 進入點（GUI / --cli / --migrate / --gui-selftest）
│   ├── crypto.py             # 金鑰衍生、Feistel、encrypt_id / decrypt_id
│   ├── folder_scanner.py     # 掃描（分層）、加密複製、群組與檔案分流、原地改名
│   ├── csv_reporter.py       # summary / processed CSV、表頭升級、備份
│   ├── pipeline.py           # 完整流程（GUI 與 CLI 共用）
│   ├── migrate.py            # 舊版結構升級（列計畫 / 執行）
│   └── gui.py                # tkinter GUI
├── tests/
│   ├── test_crypto.py
│   ├── test_scanner.py
│   ├── test_csv_reporter.py
│   ├── test_pipeline.py
│   └── test_migrate.py
├── scripts/
│   ├── instance_test.py      # 打包前後實例測試
│   └── make_manual_fixtures.py  # 手動測試假資料
├── workspace/                # 實例測試與手動測試產生（gitignore）
├── IDMasker.spec
├── paths.example.txt         # 路徑設定範本（paths.txt 已 gitignore）
├── run.bat
├── pyproject.toml
└── requirements.txt
```
