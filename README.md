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