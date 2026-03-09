#!/usr/bin/env python3
import argparse, sys, time, json, re
from pathlib import Path
from collections import Counter
from urllib.parse import urlparse, urlunparse

from playwright.sync_api import sync_playwright, TimeoutError as PWTimeoutError, Error as PWError

SECURITY_HEADERS = [
    "Content-Security-Policy", "X-XSS-Protection", "X-Content-Type-Options",
    "Strict-Transport-Security", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy",
]
REST_6_HEADERS = [
    "X-Frame-Options", "X-XSS-Protection", "X-Content-Type-Options",
    "Strict-Transport-Security", "Referrer-Policy", "Permissions-Policy",
]
ALLOW_DUPLICATE_HEADERS = {"set-cookie"}

IMPACT_REMEDIATION = {
    "Content-Security-Policy": (
        "Increased risk of XSS, content injection, and clickjacking due to lack of enforced browser restrictions.",
        "Implement a strict Content-Security-Policy using least-privilege directives; avoid unsafe-inline/unsafe-eval and include frame-ancestors."
    ),
    "X-Frame-Options": (
        "Application may be vulnerable to clickjacking if framing is not consistently blocked across browsers.",
        "Use a single X-Frame-Options header. Prefer DENY; use SAMEORIGIN only when CSP frame-ancestors is strong and CSP has no unsafe-inline/unsafe-eval."
    ),
    "Strict-Transport-Security": (
        "Users may be exposed to SSL-stripping and man-in-the-middle attacks if HTTPS is not strictly enforced.",
        "Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload."
    ),
    "X-Content-Type-Options": (
        "Browsers may MIME-sniff responses and interpret content as executable, enabling content-type confusion attacks.",
        "Set X-Content-Type-Options: nosniff on all relevant responses."
    ),
    "Referrer-Policy": (
        "Sensitive URLs or parameters may leak through the Referer header to third parties.",
        "Set Referrer-Policy: strict-origin-when-cross-origin (or stricter if required)."
    ),
    "Permissions-Policy": (
        "Unrestricted browser features (camera/mic/geolocation) may be abused by malicious content or risky integrations.",
        "Apply Permissions-Policy to explicitly disable unused features (e.g., geolocation=(), microphone=(), camera=())."
    ),
    "X-XSS-Protection": (
        "Legacy XSS filter behavior may be disabled; older clients may lose an extra layer of mitigation.",
        "Set X-XSS-Protection appropriately (or rely on CSP as the primary modern control)."
    ),
}

# ---------------- helpers ----------------
def norm_url(u: str) -> str:
    u = str(u).strip()
    if not u:
        raise ValueError("Empty URL")
    return u if u.startswith(("http://", "https://")) else "https://" + u

def with_path(url: str, path: str) -> str:
    if not path:
        return url
    p = urlparse(url)
    path = path if path.startswith("/") else "/" + path
    return urlunparse((p.scheme, p.netloc, path, "", "", ""))

def ensure_browsers(p):
    try:
        exe = Path(p.chromium.executable_path)
    except Exception:
        exe = None
    if not exe or not exe.exists():
        print("\n❌ Playwright browser binaries are missing.\n✅ Run: python -m playwright install chromium\n")
        sys.exit(1)

def all_headers(resp, retries=1, delay=0.15):
    if resp is None:
        return {}
    for i in range(retries + 1):
        try:
            return resp.all_headers()
        except Exception:
            if i < retries:
                time.sleep(delay)
    try:
        return resp.headers
    except Exception:
        return {}

def header_counts(resp):
    if resp is None:
        return {}
    try:
        arr = resp.headers_array()
        c = Counter()
        for h in arr:
            n = (h.get("name") or "").strip().lower()
            if n:
                c[n] += 1
        return dict(c)
    except Exception:
        return {}

def is_dup(k: str, counts: dict) -> bool:
    return k not in ALLOW_DUPLICATE_HEADERS and counts.get(k, 0) > 1

def fmt_present(pairs): return "\n".join([f"{k}: {v}" for k, v in pairs]) if pairs else ""
def fmt_missing(items): return "\n".join(items) if items else ""
def fmt_raw(hdrs): return "\n".join([f"{k}: {hdrs[k]}" for k in sorted(hdrs, key=str.lower)]) if hdrs else ""

# ---------------- analysis ----------------
def analyze(headers: dict, counts: dict):
    """
    Implements requested CSP + XFO coupling logic:

    CSP:
      - Missing -> Missing/Weak
      - Duplicate -> Missing/Weak
      - If unsafe-inline OR unsafe-eval -> Missing/Weak
      - If frame-ancestors present (and no unsafe) -> Present
      - Else (no frame-ancestors) -> Missing/Weak

    XFO:
      - Missing -> Missing
      - Duplicate -> Weak
      - DENY -> Present
      - SAMEORIGIN -> Present only if CSP has frame-ancestors and CSP has NO unsafe-inline/unsafe-eval
                   -> Missing/Weak otherwise
      - Other values -> Weak (unsupported value)
    HSTS:
      - Strict validation: max-age=31536000 + includeSubDomains + preload
      - Missing/invalid/short/no includeSubDomains/no preload => Missing/Weak
    """
    h = {k.lower(): v for k, v in (headers or {}).items()}
    present, missing = [], []

    def miss(s): missing.append(s)
    def pres(name, val): present.append((name, val))

    # ----- CSP -----
    csp_key = "content-security-policy"
    csp_raw = h.get(csp_key, "")
    csp_val = csp_raw.lower() if csp_raw else ""
    csp_has_unsafe = ("unsafe-inline" in csp_val) or ("unsafe-eval" in csp_val)
    csp_has_frame_ancestors = ("frame-ancestors" in csp_val)

    if csp_key not in h:
        miss("Content-Security-Policy (missing)")
        csp_effective_ok_for_xfo = False
    elif is_dup(csp_key, counts):
        miss(f"Content-Security-Policy (weak: duplicate header, occurrences={counts.get(csp_key)})")
        csp_effective_ok_for_xfo = False
    elif csp_has_unsafe:
        miss("Content-Security-Policy (weak: contains unsafe-inline/unsafe-eval)")
        csp_effective_ok_for_xfo = False
    elif csp_has_frame_ancestors:
        pres("Content-Security-Policy", h[csp_key])
        csp_effective_ok_for_xfo = True
    else:
        # present but missing frame-ancestors => weak (your rule implied ancestors needed for present)
        miss("Content-Security-Policy (weak: missing frame-ancestors)")
        csp_effective_ok_for_xfo = False

    # ----- XFO (CSP-aware) -----
    xfo_key = "x-frame-options"
    if xfo_key not in h:
        miss("X-Frame-Options (missing)")
    elif is_dup(xfo_key, counts):
        miss(f"X-Frame-Options (weak: duplicate header, occurrences={counts.get(xfo_key)})")
    else:
        xfo_val = h[xfo_key].strip().upper()
        if xfo_val == "DENY":
            pres("X-Frame-Options", h[xfo_key].strip())
        elif xfo_val == "SAMEORIGIN":
            # Your rule:
            # - if CSP has unsafe-inline/eval => SAMEORIGIN should be missing/weak
            # - if CSP has frame-ancestors => SAMEORIGIN present
            if csp_has_unsafe:
                miss("X-Frame-Options (weak: SAMEORIGIN not accepted when CSP contains unsafe-inline/unsafe-eval)")
            elif csp_effective_ok_for_xfo:
                pres("X-Frame-Options", h[xfo_key].strip())
            else:
                miss("X-Frame-Options (weak: SAMEORIGIN without strong CSP frame-ancestors)")
        else:
            miss(f"X-Frame-Options (weak: unsupported value {h[xfo_key].strip()})")

    # ----- HSTS (strict validation restored) -----
    hsts_key = "strict-transport-security"
    if hsts_key not in h:
        miss("Strict-Transport-Security (missing)")
    elif is_dup(hsts_key, counts):
        miss(f"Strict-Transport-Security (weak: duplicate header, occurrences={counts.get(hsts_key)})")
    else:
        v = h[hsts_key].lower()
        max_age = None
        # parse max-age
        m = re.search(r"max-age\s*=\s*(\d+)", v)
        if m:
            try:
                max_age = int(m.group(1))
            except ValueError:
                max_age = None

        if max_age is None:
            miss("Strict-Transport-Security (weak: max-age missing)")
        elif max_age != 31536000:
            miss(f"Strict-Transport-Security (weak: max-age={max_age}, expected 31536000)")
        elif "includesubdomains" not in v:
            miss("Strict-Transport-Security (weak: includeSubDomains missing)")
        elif "preload" not in v:
            miss("Strict-Transport-Security (weak: preload missing)")
        else:
            pres("Strict-Transport-Security", h[hsts_key])

    # ----- Remaining headers (presence + duplicate => weak) -----
    for name in ("X-XSS-Protection", "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"):
        key = name.lower()
        if key not in h:
            miss(f"{name} (missing)")
        elif is_dup(key, counts):
            miss(f"{name} (weak: duplicate header, occurrences={counts.get(key)})")
        else:
            pres(name, h[key])

    # de-dupe while keeping order
    present = list(dict.fromkeys(present))
    missing = list(dict.fromkeys(missing))
    return present, missing

def severity(missing):
    ms = set(missing or [])
    # CSP section: missing/weak -> LOW
    csp_sev = "LOW" if any(x.startswith("Content-Security-Policy") for x in ms) else "NONE"
    # Rest-6: count missing/weak among those 6
    rest_miss = sum(1 for h in REST_6_HEADERS if any(x.startswith(h) for x in ms))
    rest_sev = "NONE" if rest_miss == 0 else ("LOW" if rest_miss == 1 else ("MEDIUM" if rest_miss == 2 else "HIGH"))
    order = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
    overall = csp_sev if order[csp_sev] >= order[rest_sev] else rest_sev
    return overall, csp_sev

# ---------------- output ----------------
def wrap_list(text, width):
    if not text:
        return [""]
    parts = text.split(", ") if ", " in text else text.split()
    lines, cur = [], ""
    sep = ", " if ", " in text else " "
    for p in parts:
        cand = f"{cur}{sep}{p}" if cur else p
        if len(cand) <= width:
            cur = cand
        else:
            if cur:
                lines.append(cur)
            cur = p
    if cur:
        lines.append(cur)
    return lines

def out_table(r):
    col1, col2 = 22, 60
    border = "+" + "-" * col1 + "+" + "-" * col2 + "+"
    pres = ", ".join([k for k, _ in r["present"]])
    miss = ", ".join(r["missing"])
    rows = [
        ("URL", wrap_list(r["url"], col2 - 2)),
        ("Status", wrap_list(str(r["status"]), col2 - 2)),
        ("Severity", wrap_list(r["severity"], col2 - 2)),
        ("CSP Header", wrap_list(r["csp_severity"], col2 - 2)),
        ("Present Headers", wrap_list(pres, col2 - 2)),
        ("Missing / Weak", wrap_list(miss, col2 - 2)),
    ]
    print("\n" + border)
    print(f"| {'Field'.ljust(col1-1)}| {'Value'.ljust(col2-1)}|")
    print(border)
    for field, lines in rows:
        for i, line in enumerate(lines):
            if i == 0:
                print(f"| {field.ljust(col1-2)} | {line.ljust(col2-2)} |")
            else:
                print(f"| {' '.ljust(col1-2)} | {line.ljust(col2-2)} |")
    print(border)

def out_json(r):
    missing_items = []
    for item in r["missing"]:
        header = item.split(" (")[0].strip()
        impact, remediation = IMPACT_REMEDIATION.get(
            header,
            ("Security risk due to missing/weak header.", "Implement the recommended header correctly and ensure it is not duplicated.")
        )
        missing_items.append({"header": header, "finding": item, "impact": impact, "remediation": remediation})

    payload = {
        "url": r["url"],
        "status": r["status"],
        "severity": r["severity"],
        "csp_header": r["csp_severity"],
        "present_headers": [{"header": k, "value": v} for k, v in r["present"]],
        "missing_headers": missing_items,
        "raw_headers": r["raw_headers_dict"],
    }
    print(json.dumps(payload, indent=2))

def out_text(r):
    print("\n===== Security Headers Check Result =====")
    print(f"URL: {r['url']}")
    print(f"Status: {r['status']}")
    print(f"Severity: {r['severity']}")
    print(f"CSP Header={r['csp_severity']}\n")

    if r["present"]:
        print("---- Present Headers ----")
        print("\n".join([f"{k}: {v}" for k, v in r["present"]]), "\n")

    if r["missing"]:
        print("---- Missing/Weak Headers ----")
        print("\n".join(r["missing"]), "\n")

    print("---- Raw Response Headers ----")
    print(r["raw_headers_text"])
    print("========================================")

# ---------------- scan ----------------
def scan(browser, raw, timeout, path="", storage_state=""):
    url = with_path(norm_url(raw), path)
    host = urlparse(url).netloc.lower()

    ctx_kwargs = {"ignore_https_errors": True}
    if storage_state:
        ctx_kwargs["storage_state"] = storage_state
    ctx = browser.new_context(**ctx_kwargs)

    try:
        try:
            ctx.set_extra_http_headers({"Cache-Control": "no-cache", "Pragma": "no-cache"})
        except Exception:
            pass

        page = ctx.new_page()
        page.set_default_timeout(timeout)

        nav = []
        page.on("response", lambda r: nav.append(r) if r.request.is_navigation_request() else None)

        resp = page.goto(url, wait_until="domcontentloaded")
        try:
            page.wait_for_load_state("networkidle", timeout=min(timeout, 25000))
        except Exception:
            pass

        chosen = None
        if resp:
            try:
                if urlparse(resp.url).netloc.lower() == host:
                    chosen = resp
            except Exception:
                pass
        if not chosen:
            for r in reversed(nav):
                try:
                    if urlparse(r.url).netloc.lower() == host:
                        chosen = r
                        break
                except Exception:
                    pass
        if not chosen:
            chosen = resp

        if not chosen:
            return {"url": url, "status": "Failed: No navigation response captured", "severity": "NONE", "csp_severity": "NONE",
                    "present": [], "missing": ["No navigation response captured"], "raw_headers_dict": {}, "raw_headers_text": ""}

        hdrs = all_headers(chosen)
        counts = header_counts(chosen)
        present, missing = analyze(hdrs, counts)
        sev, csp_sev = severity(missing)

        return {
            "url": url,
            "status": chosen.status,
            "severity": sev,
            "csp_severity": csp_sev,
            "present": present,
            "missing": missing,
            "raw_headers_dict": hdrs,
            "raw_headers_text": fmt_raw(hdrs),
        }

    except (PWTimeoutError, PWError) as e:
        return {"url": url, "status": "Failed", "severity": "NONE", "csp_severity": "NONE",
                "present": [], "missing": [str(e)], "raw_headers_dict": {}, "raw_headers_text": ""}
    except Exception as e:
        return {"url": url, "status": "Failed", "severity": "NONE", "csp_severity": "NONE",
                "present": [], "missing": [str(e)], "raw_headers_dict": {}, "raw_headers_text": ""}
    finally:
        ctx.close()

def capture_state(browser, start_url, timeout, out_path):
    ctx = browser.new_context(ignore_https_errors=True)
    page = ctx.new_page()
    page.set_default_timeout(timeout)
    page.goto(start_url, wait_until="domcontentloaded")
    print("\n🔐 Browser opened (headed). Complete login.")
    input("After login + app loaded, press ENTER to save storage state... ")
    ctx.storage_state(path=out_path)
    ctx.close()
    print(f"\n✅ Storage state saved to: {out_path}\n")

# ---------------- main ----------------
def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--url", help="Single URL/host to scan")
    g.add_argument("--input", help="Input .xlsx (first column URLs)")
    ap.add_argument("--output", help="Output .xlsx report")
    ap.add_argument("--timeout", type=int, default=90000)
    ap.add_argument("--path", default="")
    ap.add_argument("--storage-state", default="")
    ap.add_argument("--capture-storage-state", default="")
    ap.add_argument("--headed", action="store_true")
    ap.add_argument("--browser", choices=["chromium", "chrome", "msedge"], default="chromium")
    ap.add_argument("--format", choices=["text", "table", "json"], default="text")
    args = ap.parse_args()

    # Lazy import pandas only when Excel is used
    if args.input or args.output:
        import pandas as pd  # noqa: F401

    with sync_playwright() as p:
        ensure_browsers(p)
        launch_kwargs = dict(headless=not args.headed, args=["--ignore-certificate-errors"])
        if args.browser in ("chrome", "msedge"):
            launch_kwargs["channel"] = args.browser
        browser = p.chromium.launch(**launch_kwargs)

        if args.capture_storage_state:
            if not args.url:
                print("❌ --capture-storage-state requires --url")
                browser.close()
                sys.exit(1)
            capture_state(browser, with_path(norm_url(args.url), args.path), args.timeout, args.capture_storage_state)
            browser.close()
            return

        results = []
        if args.input:
            import pandas as pd
            df = pd.read_excel(args.input, engine="openpyxl")
            urls = df.iloc[:, 0].dropna().astype(str).tolist()
            results = [scan(browser, u, args.timeout, args.path, args.storage_state) for u in urls]
        else:
            results = [scan(browser, args.url, args.timeout, args.path, args.storage_state)]

        browser.close()

    # Single URL output
    if args.url:
        r = results[0]
        if args.format == "json":
            out_json(r)
        elif args.format == "table":
            out_table(r)
        else:
            out_text(r)

    # Excel output
    if args.output:
        import pandas as pd
        out = pd.DataFrame([{
            "urls scanned": r["url"],
            "status code(if failed include reason)": str(r["status"]),
            "Severity": r["severity"],
            "CSP Header": r["csp_severity"],
            "Present header": "\n".join([f"{k}: {v}" for k, v in r["present"]]),
            "Missing headers": "\n".join(r["missing"]),
            "Raw response": r["raw_headers_text"],
        } for r in results])
        out.to_excel(args.output, index=False, engine="openpyxl")
        print(f"\n✅ Done. Report generated: {args.output}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)