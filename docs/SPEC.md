# IDMasker - 資料夾去識別化工具 需求規格書

本文件描述程式**目前的實際行為**。格式演進見 git log。

## 1. 概述

將含有可識別編號的病例資料夾，透過 FPE（Format-Preserving Encryption）概念的加密，
複製成去識別化名稱的輸出。原始資料夾保留不動；檔案內容不做改動，只改名稱與擺放位置。

加密為確定性：同密碼 + 同病歷號永遠得到同一結果；持有密碼者可還原病歷號。

來源分兩個群組，同一次掃描依名稱格式自動辨識：

| 群組 | 來源資料夾名稱格式 | 長度 |
|------|------|------|
| patient | `XXXXXXXXYYYYMMDDHHMMSS` | 22 碼 |
| control | `IIIIIIIIIIXXXXXXXXYYYYMMDDHHMMSS` | 32 碼 |

- `IIIIIIIIII`：10 碼身份證號（1 英文 + 1 英數 + 8 數字，接受大小寫）
- `XXXXXXXX`：8 碼純數字病歷號（**加密目標**）
- `YYYYMMDDHHMMSS`：14 碼日期時間（**保留不動**）

## 2. 名稱轉換

### 2.1 加密後名稱
```
patient   YYYYMMDDHHMMSS_LLLLLLLLDDDD        共 27 碼
control   YYYYMMDDHHMMSS_EEEEEEEEEEDDDD      共 29 碼
```
- 日期時間移到前方，底線分隔，後接一段 token
- patient 的 token：`LLLLLLLL` 8 個英文字母（大小寫混合），由病歷號**前 4 碼**加密而來；`DDDD` 為病歷號**末 4 碼，保留明文**
- control 的 token：`EEEEEEEEEE` 10 個英文字母（大小寫混合），由身份證號**前 6 碼**加密而來；`DDDD` 為身份證號**末 4 碼，保留明文**
- 兩群組靠 token 長度區分（8 英文 vs 10 英文）
- control 的病歷號**不進入**輸出名稱，只記錄在 summary.csv / processed.csv
- token 都可用密碼還原

### 2.2 範例（字母部分為示意）
```
patient  1234567820260206082130             ->  20260206082130_xKpRmNvB5678
control  A1234567891234567820260206082130   ->  20260206082130_qWeRtYuIoP6789
還原     20260206082130_xKpRmNvB5678        ->  1234567820260206082130
還原     20260206082130_qWeRtYuIoP6789      ->  A12345678920260206082130（身份證號 + 日期時間；病歷號需查 summary.csv）
```

## 3. 操作流程（GUI）

1. 選擇來源資料夾、輸出資料夾、summary.csv 存放資料夾
2. 輸入密碼兩次（可勾「顯示密碼」）
3. 「掃描資料夾」：列出所有符合 patient / control 格式的子資料夾，清單前綴 `[patient]` / `[control]`，預設全勾；狀態列顯示各群組數量
4. 「執行加密」：
   - 若 summary.csv 已存在且密碼與既有紀錄不同，跳出警告並詢問是否繼續
   - 逐一加密、複製到輸出目錄（見第 4 節）
   - 輸出目錄該群組已有同名結果者跳過
   - 寫入 summary.csv、processed.csv，並備份（見第 6 節）
5. 顯示成功（含各群組數）/ 跳過 / 失敗數與明細

### 3.1 無介面模式（CLI）
GUI 與 CLI 共用 `src/pipeline.py` 的 `run_encryption`，流程完全相同。CLI 供自動化與打包後測試：
```
IDMasker.exe --cli --source <來源夾> --output <輸出夾> --csv-dir <summary.csv 夾> --password <密碼>
             [--backup-dir <備份夾>] [--folders <名稱> ...] [--report <結果.json>]
```
- `--backup-dir` 省略時用 `paths.txt` 的 `BACKUP_DIR`；`--folders` 省略時處理全部符合格式者
- `--report` 把逐筆結果與計數寫成 JSON（windowed exe 沒有 console，靠這個拿結果）
- exit code：0 全部成功或跳過、1 有失敗、2 參數不足
- `--gui-selftest [--report <json>]`：建一次主視窗再關掉，回報 Tcl 版本與 tcl_library；
  exit 0 成功、1 失敗。用來驗證打包後 tkinter 可用（只看行程存活會把錯誤對話框誤判成成功）

## 4. 輸出結構

```
<輸出資料夾>/
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
- 同日期時間的 patient 與 control：token 不同（patient 用病歷號 8 英文、control 用身份證號 10 英文），且分屬不同群組樹

## 5. 加密方案

### 5.1 金鑰衍生
PBKDF2-HMAC-SHA256，固定 salt `IDMasker_v1_salt`，100,000 次迭代，256-bit key。
固定 salt 是刻意的：確保同密碼 + 同輸入 = 同輸出。

### 5.2 病歷號加密（`encrypt_id`）
1. 取前 4 碼為整數 n（0~9999）
2. 8 輪 Feistel 網絡（左右各 0~99，輪函數 HMAC-SHA256），得 m（0~9999），一對一映射
3. 以 HMAC-SHA256(key, `"letters:"` + m) 前 8 bytes 各 mod 52 映射至 `A-Za-z`，得 8 個字母
4. 輸出 = 8 字母 + 原末 4 碼

### 5.3 病歷號解密（`decrypt_id`）
窮舉 m 於 0~9999 比對 8 字母，再做 Feistel 逆運算。密碼錯誤時找不到匹配，拋出 `ValueError`。

### 5.4 身份證號加密（`encrypt_national_id`）
1. 取前 6 碼（1 英文 + 1 英數 + 4 數字）編成混合進位整數 n：第 1 碼在 52 個英文字母的索引、
   第 2 碼在 62 個英數的索引、後 4 碼數字；合法範圍 52×62×10^4 ≈ 3.2×10^7
2. 在 52^10（≈ 1.4×10^17）空間做 10 輪 Feistel（左右各 52^5，輪函數 HMAC-SHA256，
   域標籤 `"nid:"` 與病歷號區隔），得 m，一對一映射
3. m 以 52 進位編成 10 個英文字母（每個位置都有完整 52 種變化，無前導 A 問題）
4. 輸出 = 10 字母 + 原末 4 碼，共 14 碼

### 5.5 身份證號解密（`decrypt_national_id`）
10 字母 → m → Feistel 逆運算 → n，直接還原，不需窮舉。
密碼錯誤時 n 落在合法範圍外的機率約 1 - 2×10^-10，拋出 `ValueError`，實務上錯密碼必定報錯。

### 5.6 安全特性與限制
- 無密碼無法還原病歷號前 4 碼與身份證號前 6 碼；同密碼同輸入結果固定；一對一映射無碰撞
- 病歷號末 4 碼、身份證號末 4 碼明文外露，是刻意取捨
- 加密段全為英文字母，不會長得像真實病歷號或身份證號
- summary.csv 含原始病歷號、身份證號與**明文密碼**，是再識別鑰匙；其存放夾與備份夾不入 git、不進雲端同步

## 6. CSV 報告與備份

### 6.1 summary.csv
路徑：使用者指定的資料夾 / `summary.csv`，追加寫入，不覆寫舊紀錄。

| 欄位 | 說明 |
|---|---|
| 群組 | patient / control |
| 身份證號 | control 的 10 碼；patient 為空 |
| 原始病例編號 | 8 碼病歷號 |
| 日期 | YYYYMMDD |
| 時分秒 | HHMMSS |
| 加密前檔名 | 原始資料夾完整名稱（control 含身份證號） |
| 加密後檔名 | 27 碼加密名稱 |
| 使用密碼 | 明文 |
| JPG數量 | .jpg / .jpeg 數 |
| 有JSON / 有EDF / 有ACQ | 是 / 否 |
| 加密時間 | 執行時間 |

數字類欄位以 `="..."` 包裝，避免 Excel 掉前導 0。

### 6.2 processed.csv
路徑：來源資料夾 / `processed.csv`，追加寫入。
欄位：群組、身份證號、病例號碼、日期、時間、資料夾名稱、轉檔時間。

### 6.3 表頭升級
既有 CSV 表頭若為舊版（無「群組」「身份證號」欄），下次寫入時自動重寫為新表頭：
舊資料列群組補 `patient`、身份證號留空，其餘欄位照搬。重寫經暫存檔後原子取代，不會留下半截檔案。

### 6.4 備份
- 備份夾：`paths.txt` 的 `BACKUP_DIR`（範本 `paths.example.txt`）；缺檔或缺鍵時用 `%USERPROFILE%\Documents\IDMasker\Backups`
- 每次加密完成後自動備份，**只保留最新一版**：
  - `summary_<YYYYMMDD_HHMMSS>.csv`：寫入後刪除其他 `summary_<時間戳>.csv`
  - `processed_<來源夾名>_<YYYYMMDD_HHMMSS>.csv`：寫入後刪除**同來源夾**的其他版本，以及舊版沒有來源夾名的 `processed_<時間戳>.csv`；其他來源夾的備份不動
- summary.csv 為累積追加，最新一版備份即含全部歷史；processed.csv 正本在各來源夾
- 備份失敗不中斷主流程

## 7. 解密 / 還原

程式庫層提供（`src/folder_scanner.py`）：
- `scan_for_decryption(parent)`：列出加密格式的子資料夾（patient 27 碼、control 29 碼皆收，由 token 長度分群組）
- `rename_folders(parent, names, password, mode="decrypt")`：原地改回還原名稱

**目前 GUI 沒有解密入口**，上述功能只能在 Python 中呼叫。
patient 還原為 22 碼（病歷號 + 日期時間）；control 還原為 24 碼（身份證號 + 日期時間），病歷號須另查 summary.csv。

## 8. 技術規格

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
  在 `workspace/<mode>/` 建假資料（patient + control、干擾夾、舊版 summary.csv、舊版備份），
  以 `--cli` 跑完整流程並驗證輸出樹、CSV 升級、備份清理、可解密性與重跑全跳過；
  exe 模式另測 GUI 能啟動。備份一律指向 workspace 內，不碰真實 `BACKUP_DIR`。

### 專案結構
```
IDMasker/
├── docs/SPEC.md              # 本文件
├── src/
│   ├── main.py               # 進入點（GUI / --cli）
│   ├── crypto.py             # 金鑰衍生、Feistel、encrypt_id / decrypt_id
│   ├── folder_scanner.py     # 格式辨識、掃描、加密複製、群組與檔案分流、原地改名
│   ├── csv_reporter.py       # summary / processed CSV、表頭升級、備份
│   ├── pipeline.py           # 完整流程（GUI 與 CLI 共用）
│   └── gui.py                # tkinter GUI
├── tests/
│   ├── test_crypto.py
│   ├── test_scanner.py
│   ├── test_csv_reporter.py
│   └── test_pipeline.py
├── scripts/instance_test.py  # 打包前後實例測試
├── workspace/                # 實例測試產生（gitignore）
├── IDMasker.spec
├── paths.example.txt         # 路徑設定範本（paths.txt 已 gitignore）
├── run.bat
├── pyproject.toml
└── requirements.txt
```
