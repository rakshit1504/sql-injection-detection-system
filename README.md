# SQL Injection Detection System
## Lightweight DB-side Enforcement — Proxy + Grammar Fingerprinting

**Team: RazorShield — Rakshit Bansal (22BCE0431), Sarthak Ray (22BCE3380)**

### Project Overview
This repository implements a lightweight, explainable SQL Injection (SQLi) detection and prevention prototype. A Flask proxy intercepts SQL queries, normalizes them into structural fingerprints, and enforces a whitelist of approved fingerprints. Queries that do not match the whitelist are blocked and logged.

This design prioritizes interpretability, ease of deployment, and low operational overhead—suitable for research, demonstrations, and lightweight production prototypes.

### Features
- Grammar-based fingerprinting: replace literals with placeholders and normalize keywords.
- Whitelist enforcement of safe query fingerprints.
- Flask proxy that intercepts queries before they reach the database.
- SQLite-backed execution for allowed queries.
- Evaluation scripts and automated test harness.
- Human-readable whitelist (`whitelist.json`) for audit and review.

### Repository Structure
```
.
├── dataset/
│   └── queries.csv          # Labeled queries: query,label
├── src/
│   ├── fingerprint.py       # Query normalization
│   ├── whitelist.py         # Whitelist load/check/update
│   ├── train.py             # Build whitelist from dataset
│   ├── proxy.py             # Flask proxy server
│   ├── evaluate.py          # Evaluation script (metrics)
│   └── test_proxy.py        # Integration tests
├── whitelist.json           # Generated whitelist (can be regenerated)
├── requirements.txt
└── README.md
```

### Requirements
- Python 3.10 or newer
- `pip`
- Recommended: virtual environment (`venv`)
- Python packages (see `requirements.txt`):
  - Flask
  - pandas
  - scikit-learn
  - requests

**Install dependencies:**
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

pip install -r requirements.txt
```

### Quick Start — Run Locally
1.  **Train the whitelist** (generates `whitelist.json` from `dataset/queries.csv`):
    ```bash
    python src/train.py
    ```
2.  **Start the Flask proxy:**
    ```bash
    python src/proxy.py
    ```
    Default address: `http://127.0.0.1:5001`

Send queries (examples below) or use the provided PowerShell helper for Windows.

### API Endpoints
- `POST /query` — submit a SQL string as JSON: `{ "query": "<SQL>" }`
- `GET /health` — healthcheck
- `GET /status` — server status
- `GET /whitelist` — current whitelist summary
- `GET /blocked` — blocked queries log

### Testing — Commands
#### Windows (PowerShell) — recommended
Paste this function into PowerShell once, then call it to test queries safely:
```powershell
function Invoke-ProxyQuery {
  param(
    [Parameter(Mandatory=$true)][string] $Query
  )

  $Url  = 'http://127.0.0.1:5001/query'
  $Body = @{ query = $Query } | ConvertTo-Json

  try {
    $Result = Invoke-RestMethod -Uri $Url -Method Post -ContentType 'application/json' -Body $Body -ErrorAction Stop
    Write-Host "`nALLOWED QUERY" -ForegroundColor Green
    $Result | Format-List
  } catch {
    $Resp = $_.Exception.Response
    if ($Resp) {
      $Reader = New-Object System.IO.StreamReader($Resp.GetResponseStream())
      $Body   = $Reader.ReadToEnd()
      $Reader.Close()
      try {
        $Json = $Body | ConvertFrom-Json
        Write-Host "`nBLOCKED QUERY" -ForegroundColor Red
        $Json | Format-List
      } catch {
        Write-Host "`nBLOCKED QUERY (non-JSON body)" -ForegroundColor Red
        Write-Host $Body
      }
    } else {
      Write-Host "REQUEST FAILED: $($_.Exception.Message)" -ForegroundColor Red
    }
  }
}
```
**Usage:**
```powershell
# Allowed (normal) query
Invoke-ProxyQuery -Query "SELECT * FROM users WHERE id=1"

# Blocked (SQLi) example
Invoke-ProxyQuery -Query "SELECT * FROM users WHERE id='1' OR '1'='1'"
```

#### curl — Windows (cmd.exe)
Open `cmd.exe` (not PowerShell) and run:
```bash
# Allowed
curl -X POST http://127.0.0.1:5001/query -H "Content-Type: application/json" -d "{\"query\":\"SELECT * FROM users WHERE id=1\"}"

# Blocked
curl -X POST http://127.0.0.1:5001/query -H "Content-Type: application/json" -d "{\"query\":\"SELECT * FROM users WHERE id='1' OR '1'='1'\"}"
```

#### curl — macOS / Linux / Git Bash
```bash
# Allowed
curl -X POST http://127.0.0.1:5001/query -H "Content-Type: application/json" -d '{ "query": "SELECT * FROM users WHERE id=1" }'

# Blocked
curl -X POST http://127.0.0.1:5001/query -H "Content-Type: application/json" -d '{ "query": "SELECT * FROM users WHERE id='\''1'\'' OR '\''1'\''='\''1'\''" }'
```

### Evaluation
Run the evaluation script to compute accuracy, precision, recall, F1 and save results:
```bash
python src/evaluate.py
```
**Example output (controlled dataset):**
```
Accuracy: 1.0000 (100.00%)
Precision: 1.0000 (100.00%)
Recall: 1.0000 (100.00%)
F1 Score: 1.0000 (100.00%)
```
`evaluation_results.json` is created/updated with the run summary.

### Development Notes
- `fingerprint.py` normalizes queries by replacing string and numeric literals with `?`, removing comments, and uppercasing keywords.
- `train.py` builds `whitelist.json` from labeled normal queries in `dataset/queries.csv`.
- `proxy.py` enforces the whitelist and executes allowed queries on a local SQLite DB (`proxy_db.sqlite`).
- To expand the whitelist safely, use a staged learning mode: gather candidate fingerprints, manually review them, then add.

### Demo Checklist (recommended before presentation)
1.  Activate your virtual environment.
2.  Run `python src/train.py` and show whitelist generation.
3.  Start proxy: `python src/proxy.py`.
4.  In PowerShell: paste the `Invoke-ProxyQuery` function, then run sample queries.
5.  Show `/blocked` and `/whitelist` endpoints results.

### Contribution
- Fork the repo, create a feature branch, run tests locally, then open a pull request.
- Keep whitelist updates auditable: automatic additions must be subject to manual review.

### Appendix / Attachments
- Add screenshots for:
  - `python src/train.py` output
  - `python src/evaluate.py` output
  - Proxy run with allowed & blocked sample queries
- Include source files under `src/` in the appendix section of any formal report.

### License & Usage
This project is provided for academic and research use. It is not hardened for production use. Review and harden before any live deployment.

### Contact
Team RazorShield — Rakshit Bansal (22BCE0431), Sarthak Ray (22BCE3380)





# SQL Injection Detection System

A lightweight SQL injection detection system using proxy interception and grammar fingerprinting.

## Overview

This system intercepts SQL queries before they reach the database, normalizes them into fingerprints, and checks against a whitelist of allowed query patterns. Any query whose fingerprint doesn't match the whitelist is flagged as potentially malicious.

## Features

- **Query Fingerprinting**: Normalizes SQL queries by replacing literals with placeholders
- **Whitelist Training**: Builds a whitelist from known good queries
- **Proxy Interception**: Simulates query interception using Flask
- **Detection Engine**: Flags suspicious queries not in the whitelist
- **Evaluation Tools**: Measures detection accuracy, precision, and recall

## Project Structure

```
├── dataset/
│   └── queries.csv      # Sample dataset of normal + SQLi queries
├── src/
│   ├── proxy.py         # Proxy server for intercepting queries
│   ├── fingerprint.py   # Query normalization/fingerprinting
│   ├── whitelist.py     # Whitelist management
│   ├── train.py         # Whitelist training from dataset
│   └── evaluate.py      # System evaluation
├── requirements.txt     # Python dependencies
└── README.md           # This file
```

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Train the system:
   ```bash
   python src/train.py
   ```

3. Start the proxy server:
   ```bash
   python src/proxy.py
   ```

4. Evaluate performance:
   ```bash
   python src/evaluate.py
   ```

## Usage

The proxy server runs on `http://localhost:5000` and accepts POST requests with SQL queries:

```bash
curl -X POST http://localhost:5000/query \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT * FROM users WHERE id=1"}'
```

## Technical Approach

1. **Fingerprinting**: Queries like `SELECT * FROM users WHERE id=42` become `SELECT * FROM users WHERE id=?`
2. **Training**: Normal queries are fingerprinted and stored in a whitelist
3. **Detection**: Runtime queries are fingerprinted and checked against the whitelist
4. **Enforcement**: Non-matching queries are blocked and logged

## Requirements

- Python 3.10+
- Flask for proxy simulation
- pandas for data handling
- SQLite3 for lightweight database operations
