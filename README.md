# 🛰️ IP Enrichment Utility (`ip_enrich`)

**ip_enrich** enriches IP addresses with ownership and routing metadata using **Team Cymru WHOIS**, **RDAP**, and **DNS** lookups.  

It supports both **single‑IP reporting** (human‑readable) and **CSV enrichment** (machine‑readable).  
Built‑in caching and a polite `--sleep` delay help avoid rate limits.

---

## 🚀 Features

- **Team Cymru WHOIS** – routing view: ASN, BGP prefix, country, registry, allocation date  
- **RDAP** – registry/ownership view: org name, country, ASN details, handles  
- **DNS PTR** – reverse hostname
- **Two modes**
  1) Single‑IP report → formatted text to stdout  
  2) CSV enrichment → adds selected fields as new columns
- Container‑friendly (no local state required)

---

## 🧰 Installation

With Conda (recommended):

```bash
conda env create -f environment.yml
conda activate ip_enrich
```

Or with pip:

```bash
python -m venv .venv && source .venv/bin/activate
pip install ipwhois dnspython requests
```

---

## 🧩 Usage

### 1) Single‑IP Report

```bash
python ip_enrich.py 8.8.8.8
```

Example output:

```
IP Intelligence Report for 8.8.8.8
==================================
PTR              dns.google
ASN              15169
ASN Name         GOOGLE - Google LLC
BGP Prefix       8.8.8.0/24
Country (CC)     US
Registry         arin
Allocated        1992-12-01
RDAP Org         Google LLC
RDAP Country     US
ASN CIDR         8.8.8.0/24
RDAP Handle      GOOGLE
```

> Tip: Output varies depending on available data from Cymru/RDAP and DNS.

### 2) CSV Enrichment

```bash
python ip_enrich.py input.csv --ip-column dest_ip --output enriched.csv
```

**Common options**

| Option | Description |
|---|---|
| `--ip-column` | CSV column containing IP addresses (default: `ip`) |
| `--prefix` | Prefix for added columns (default: empty) |
| `--fields` | Comma‑separated list of fields to add (see Field Reference) |
| `--delimiter` | Input CSV delimiter (default `,`; use `\\t` for TSV) |
| `--sleep` | Delay between lookups in seconds (default `0.2`) |
| `--output` | Output file path (default: stdout) |

**Examples**

Add default field set with a prefix:
```bash
python ip_enrich.py flows.csv \
  --ip-column src_ip \
  --prefix net_ \
  --output flows_enriched.csv
```

Pick specific fields:
```bash
python ip_enrich.py flows.csv \
  --ip-column ip \
  --fields asn,asn_name,bgp_prefix,rdap_org \
  --output out.csv
```

---

## 🧠 Field Reference (Complete)

### ✅ Recommended Default Fields
These provide strong attribution with minimal noise:
```
asn, asn_name, bgp_prefix, cc, rdap_org, rdap_country
```

### 🌐 All Fields (alphabetical, with descriptions)

| Field | Source | Description |
|---|---|---|
| **allocated** | Team Cymru | Allocation date for the IP block observed by Team Cymru. |
| **asn** | Team Cymru / RDAP | Autonomous System Number announcing/owning the IP. |
| **asn_cidr** | RDAP | CIDR range for the ASN from RDAP (when provided). |
| **asn_name** | Team Cymru / RDAP | Human‑readable name of the ASN (e.g., `AMAZON-02 - Amazon.com, Inc.`). |
| **bgp_prefix** | Team Cymru | Announced BGP prefix covering the IP address. |
| **cc** | Team Cymru | Country code inferred from routing data (Cymru’s view). |
| **ptr** | DNS | Reverse DNS hostname (PTR record), if present. |
| **rdap_country** | RDAP | Country code from registry ownership data (RDAP’s view). |
| **rdap_handle** | RDAP | Registry/Network handle identifier for the RDAP record. |
| **rdap_org** | RDAP | Registered organization short name from RDAP. |
| **rdap_org_full** | RDAP | Longer organization/remarks text (can be verbose). |
| **registry** | Team Cymru | Regional Internet Registry (e.g., `arin`, `ripe`, `apnic`). |

> Notes:  
> • **Team Cymru** reflects current routing reality; **RDAP** reflects registry ownership.  
> • Some fields may be empty if the upstream source did not provide them for a given IP.

---

## 🧩 Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `HTTPLookupError` or timeouts | RDAP rate limiting or network egress restrictions → increase `--sleep`, or retry later. |
| Empty `ptr` | No reverse DNS exists for that IP. |
| Missing `asn`/`bgp_prefix` | IP may not be publicly routed. |
| Slow lookups | Ensure DNS is responsive; consider local resolver cache. |
| `whois.cymru.com` blocked | Allow outbound TCP/43 to Team Cymru WHOIS. |

---

## 📄 License

Apache 2.0 — NCSA (2025).  
Designed for containerized network attribution and IP enrichment workflows.
