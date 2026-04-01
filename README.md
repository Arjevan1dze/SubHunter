# 🔍 SubHunter

> Automated subdomain reconnaissance framework for bug bounty hunting and penetration testing.

![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=flat)

---

## 📌 What is SubHunter?

SubHunter is a subdomain reconnaissance tool built for bug bounty hunters and penetration testers. It combines multiple passive enumeration sources

---

## ⚙️ How It Works

### Phase 1 — Subdomain Enumeration
- **Subfinder** — passive enumeration across all sources, recursive
- **Amass** — passive DNS enumeration
- **Assetfinder** — fast subdomain discovery
- **crt.sh** — certificate transparency log search

All results are merged and deduplicated into `Unfiltered.txt`

### Phase 2 — Live Host Filtering
- **HTTPX** — probes all subdomains for live hosts
- Detects: status codes, page titles, web technologies
- Matches: `200, 201, 301, 302, 403, 401, 500`
- Output saved to `Alive.txt`
- `Unfiltered.txt` is automatically deleted after

---

## 🛠️ Requirements

### Required tools
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [httpx](https://github.com/projectdiscovery/httpx)
- Python 3.x + `requests` library (`pip install requests`)

### Optional tools (skipped gracefully if missing)
- [amass](https://github.com/owasp-amass/amass)
- [assetfinder](https://github.com/tomnomnom/assetfinder)

---

## 🚀 Usage
```bash
python3 SubHunter.py
```

Enter your target when prompted — any format works:
```
example.com
https://example.com
http://example.com/
```

---

Made by [Arjevan1dze](https://github.com/Arjevan1dze)
