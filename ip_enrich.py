#!/usr/bin/env python3
# ip_enrich.py
import sys, csv, re, socket, argparse, json, time, os
from pathlib import Path

# External deps:
#   pip install ipwhois dnspython
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError, HTTPLookupError, ASNLookupError
import dns.resolver
import dns.reversename

# -------------------- Field Catalog --------------------
# All fields you can request via --fields (keys) with a short explanation (values)
FIELD_DESCRIPTIONS = {
    # DNS
    "ptr": "Reverse DNS (PTR) hostname, if available",

    # Team Cymru WHOIS (routing perspective)
    "asn": "Autonomous System Number (Team Cymru / RDAP fallback)",
    "asn_name": "Autonomous System name (e.g., AMAZON-02 - Amazon.com, Inc.)",
    "bgp_prefix": "Routed BGP prefix that covers the IP",
    "cc": "Country code inferred by Team Cymru (routing data)",
    "registry": "Registry/RIR reported by Team Cymru (e.g., arin, ripe)",
    "allocated": "IP block allocation date observed by Team Cymru",

    # RDAP (ownership/registry perspective)
    "rdap_org": "Registered organization (RDAP network/owner name)",
    "rdap_org_full": "Longer org/remarks text (may be verbose)",
    "rdap_country": "Country reported by RDAP (owner/registry view)",
    "asn_cidr": "CIDR range reported by RDAP",
    "rdap_handle": "RDAP/registry handle for the network record",
}

# A sensible, compact default set for most workflows:
DEFAULT_FIELDS = ["asn", "asn_name", "bgp_prefix", "cc", "rdap_org", "rdap_country"]

# -------------------- Utilities --------------------
def is_ip(s):
    if not s: return False
    try:
        socket.inet_aton(s); return True
    except:
        try:
            socket.inet_pton(socket.AF_INET6, s); return True
        except:
            return False

_dns_cache = {}
def reverse_dns(ip):
    if not ip: return ""
    if ip in _dns_cache: return _dns_cache[ip]
    try:
        name = dns.reversename.from_address(ip)
        ans = dns.resolver.resolve(name, "PTR")
        ptr = str(ans[0]).rstrip(".")
        _dns_cache[ip] = ptr
        return ptr
    except:
        _dns_cache[ip] = ""
        return ""

_rdap_cache = {}
def rdap_lookup(ip):
    if not ip: return {}
    if ip in _rdap_cache: return _rdap_cache[ip]
    try:
        data = IPWhois(ip).lookup_rdap(asn_methods=["dns", "whois", "http"])
        res = {
            "rdap_org": (data.get("network") or {}).get("name") or "",
            "rdap_org_full": (data.get("network") or {}).get("remarks") or "",
            "rdap_country": data.get("asn_country_code") or (data.get("network") or {}).get("country") or "",
            "asn": data.get("asn") or "",
            "asn_description": data.get("asn_description") or "",
            "asn_cidr": data.get("asn_cidr") or "",
            "rdap_handle": (data.get("network") or {}).get("handle") or "",
            # keep raw around for debugging, but we won't emit it
            "rdap_raw": data.get("network") or {},
        }
        _rdap_cache[ip] = res
        return res
    except (IPDefinedError, HTTPLookupError, ASNLookupError, Exception):
        _rdap_cache[ip] = {}
        return {}

_cymru_cache = {}
def cymru_asn(ip):
    """
    Team Cymru whois: whois -h whois.cymru.com " -v <ip>"
    Columns for -v:
      AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
    """
    if not ip: return {}
    if ip in _cymru_cache: return _cymru_cache[ip]
    try:
        q = " -v " + ip
        with socket.create_connection(("whois.cymru.com", 43), 5) as s:
            s.sendall(q.encode() + b"\n")
            data = s.recv(65535).decode(errors="ignore").splitlines()
        res = {}
        for line in data[::-1]:
            if line.strip() and not line.lower().startswith("as") and "|" in line:
                parts = [x.strip() for x in line.split("|")]
                # Expected len >= 7
                if len(parts) >= 7:
                    res = {
                        "asn": parts[0],
                        # parts[1] is the echoed IP
                        "bgp_prefix": parts[2],
                        "cc": parts[3],
                        "registry": parts[4],
                        "allocated": parts[5],
                        "asn_name": parts[6],
                    }
                    break
        _cymru_cache[ip] = res
        return res
    except:
        _cymru_cache[ip] = {}
        return {}

def collect_fields_for_ip(ip):
    """Return a unified dict of all supported fields for a single IP."""
    cymru = cymru_asn(ip) if ip else {}
    rdap = rdap_lookup(ip) if ip else {}
    ptr = reverse_dns(ip) if ip else ""

    # build unified map; RDAP may complement Cymru
    out = {}
    out["ptr"] = ptr
    out["asn"] = cymru.get("asn") or rdap.get("asn") or ""
    out["asn_name"] = cymru.get("asn_name") or rdap.get("asn_description") or ""
    out["bgp_prefix"] = cymru.get("bgp_prefix") or ""
    out["cc"] = cymru.get("cc") or ""
    out["registry"] = cymru.get("registry") or ""
    out["allocated"] = cymru.get("allocated") or ""
    out["rdap_org"] = rdap.get("rdap_org") or ""
    out["rdap_org_full"] = rdap.get("rdap_org_full") or ""
    out["rdap_country"] = rdap.get("rdap_country") or ""
    out["asn_cidr"] = rdap.get("asn_cidr") or ""
    out["rdap_handle"] = rdap.get("rdap_handle") or ""
    return out

# -------------------- CSV Enrichment --------------------
def enrich_csv(input_csv, ip_col, fields, prefix, delimiter=",", sleep=0.2, output_path=None):
    delim = "\t" if delimiter == "\\t" else delimiter
    with open(input_csv, newline="") as f:
        r = csv.DictReader(f, delimiter=delim)
        rows = list(r)

    # prepare output header
    fieldnames = list(rows[0].keys()) if rows else []
    add_cols = [prefix + f for f in fields if (prefix + f) not in fieldnames]
    out_fields = fieldnames + add_cols

    out_fh = open(output_path, "w", newline="") if output_path else sys.stdout
    try:
        w = csv.DictWriter(out_fh, fieldnames=out_fields)
        w.writeheader()

        for row in rows:
            ip = (row.get(ip_col) or "").strip()
            vals = collect_fields_for_ip(ip) if ip else {}
            for f in fields:
                row[prefix + f] = vals.get(f, "")
            w.writerow(row)
            time.sleep(sleep)
    finally:
        if output_path:
            out_fh.close()

# -------------------- Human-Readable Report --------------------
def report_ip(ip):
    vals = collect_fields_for_ip(ip)
    lines = []
    def add(k, v):
        if v is not None and v != "": lines.append(f"{k:16} {v}")

    print(f"IP Intelligence Report for {ip}")
    print("=" * (26 + len(ip)))
    add("PTR", vals.get("ptr", ""))
    add("ASN", vals.get("asn", ""))
    add("ASN Name", vals.get("asn_name", ""))
    add("BGP Prefix", vals.get("bgp_prefix", ""))
    add("Country (CC)", vals.get("cc", ""))
    add("Registry", vals.get("registry", ""))
    add("Allocated", vals.get("allocated", ""))
    add("RDAP Org", vals.get("rdap_org", ""))
    add("RDAP Country", vals.get("rdap_country", ""))
    add("ASN CIDR", vals.get("asn_cidr", ""))
    add("RDAP Handle", vals.get("rdap_handle", ""))
    if vals.get("rdap_org_full"):
        # rdap_org_full can be long; show a trimmed preview
        full = vals["rdap_org_full"]
        preview = full if len(full) < 300 else (full[:300] + "...")
        add("RDAP Org Full", preview)
    print("\n".join(lines) if lines else "(no data)")

# -------------------- CLI --------------------
def build_parser():
    desc = "Enrich IPs using Team Cymru (routing) and RDAP (registry) data.\n\n" \
           "USAGE MODES:\n" \
           "  1) Single-IP report (human readable):\n" \
           "       ip_enrich.py 8.8.8.8\n" \
           "  2) CSV enrichment (writes CSV to stdout by default):\n" \
           "       ip_enrich.py input.csv --ip-column src_ip --prefix asn_ " \
           "--fields asn,asn_name,bgp_prefix,cc,rdap_org,rdap_country\n\n" \
           "AVAILABLE FIELDS:\n" + "\n".join([f"  - {k}: {v}" for k,v in FIELD_DESCRIPTIONS.items()])

    ap = argparse.ArgumentParser(
        description=desc,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("target",
        help="Either a single IP (e.g., 8.8.8.8) for a human-readable report, "
             "or a CSV file path for enrichment.")
    ap.add_argument("--ip-column", default="ip",
        help="(CSV mode) Column name containing IP addresses (default: ip).")
    ap.add_argument("--prefix", default="",
        help="(CSV mode) Prefix for new columns (default: empty string).")
    ap.add_argument("--fields",
        help="(CSV mode) Comma-separated subset of fields to add. "
             "Default: " + ",".join(DEFAULT_FIELDS))
    ap.add_argument("--delimiter", default=",",
        help="(CSV mode) Input CSV delimiter (default ','). Use '\\t' for TSV.")
    ap.add_argument("--sleep", type=float, default=0.2,
        help="(CSV mode) Sleep between lookups to be polite (default 0.2s).")
    ap.add_argument("--output",
        help="(CSV mode) Output file path. If omitted, writes to stdout.")
    return ap

def main():
    ap = build_parser()
    args = ap.parse_args()

    # Decide mode: IP vs CSV file
    if is_ip(args.target):
        # Single-IP report
        report_ip(args.target)
        return

    # Else treat as CSV path
    csv_path = Path(args.target)
    if not csv_path.exists() or not csv_path.is_file():
        print(f"Error: '{args.target}' is neither an IP nor a readable CSV file.", file=sys.stderr)
        sys.exit(2)

    # Parse fields selection
    if args.fields:
        fields = [x.strip() for x in args.fields.split(",") if x.strip()]
    else:
        fields = list(DEFAULT_FIELDS)

    # Validate requested fields
    unknown = [f for f in fields if f not in FIELD_DESCRIPTIONS]
    if unknown:
        print("Error: unknown field(s): " + ", ".join(unknown), file=sys.stderr)
        print("Use --help to see the full list of available fields.", file=sys.stderr)
        sys.exit(2)

    enrich_csv(
        input_csv=str(csv_path),
        ip_col=args.ip_column,
        fields=fields,
        prefix=args.prefix,
        delimiter=args.delimiter,
        sleep=args.sleep,
        output_path=args.output
    )

if __name__ == "__main__":
    main()
