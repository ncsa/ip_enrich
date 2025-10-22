# 🛰️ IP Enrichment Utility (`ip_enrich.py`)

**ip_enrich** enriches IP addresses with network ownership and routing metadata using **Team Cymru WHOIS** and **RDAP** lookups.  
It supports both **single-IP reporting** (human-readable output) and **CSV enrichment** (machine-readable output with additional columns).  
Optional **whitelisting** lets you mark known, trusted, or low-risk networks.

---

## 🚀 Features

- Look up IPs via:
  - **Team Cymru WHOIS** – routing / ASN / prefix / country  
  - **RDAP** – official registry / ownership / contact details  
  - **DNS PTR** – reverse hostname lookup
- Two modes:
  1. **Single IP mode:** outputs a readable report to stdout  
  2. **CSV mode:** enriches an input CSV file with extra columns
- Flexible **whitelist** system for trusted networks  
- Built-in caching for repeated lookups  
- Designed to run in **immutable containers**

---

## 🧰 Installation

Create and activate the environment:

```bash
conda env create -f environment.yml
conda activate ip_enrich
