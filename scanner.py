import requests
import time
from payloads import SQLI_PAYLOADS, XSS_PAYLOADS, SQLI_ERRORS
from crawler import crawl
from reporter import generate_report

vulnerabilities = []

def submit_form(session, form, payload, field_name):
    """Submit a form with a given payload in the specified field."""
    data = {}
    for inp in form["inputs"]:
        if inp["name"] == field_name:
            data[inp["name"]] = payload
        else:
            data[inp["name"]] = inp["value"]

    try:
        if form["method"] == "post":
            return session.post(form["action"], data=data, timeout=10)
        else:
            return session.get(form["action"], params=data, timeout=10)
    except Exception as e:
        print(f"    [!] Request failed: {e}")
        return None

def test_sqli(session, page_url, form):
    """Test a form for SQL Injection vulnerabilities."""
    for inp in form["inputs"]:
        if inp["type"] in ["submit", "hidden", "button"]:
            continue
        for payload in SQLI_PAYLOADS:
            response = submit_form(session, form, payload, inp["name"])
            if response is None:
                continue
            content = response.text.lower()
            for error in SQLI_ERRORS:
                if error in content:
                    vuln = {
                        "type": "SQL Injection",
                        "url": page_url,
                        "form_action": form["action"],
                        "field": inp["name"],
                        "payload": payload,
                        "risk": "HIGH",
                        "recommendation": "Use parameterized queries / prepared statements."
                    }
                    vulnerabilities.append(vuln)
                    print(f"  [!!!] SQLi FOUND at {page_url} — field: {inp['name']} — payload: {payload}")
                    return  # one found per field is enough for report

def test_xss(session, page_url, form):
    """Test a form for Cross-Site Scripting vulnerabilities."""
    for inp in form["inputs"]:
        if inp["type"] in ["submit", "hidden", "button"]:
            continue
        for payload in XSS_PAYLOADS:
            response = submit_form(session, form, payload, inp["name"])
            if response is None:
                continue
            if payload in response.text:
                vuln = {
                    "type": "Cross-Site Scripting (XSS)",
                    "url": page_url,
                    "form_action": form["action"],
                    "field": inp["name"],
                    "payload": payload,
                    "risk": "HIGH",
                    "recommendation": "Sanitize and encode all user inputs before rendering."
                }
                vulnerabilities.append(vuln)
                print(f"  [!!!] XSS FOUND at {page_url} — field: {inp['name']} — payload: {payload}")
                return

def run_scanner(target_url):
    print("=" * 60)
    print("   Web Vulnerability Scanner — SQLi & XSS Detection")
    print("=" * 60)
    print(f"\n[*] Target: {target_url}")

    session = requests.Session()
    start_time = time.time()

    print("\n[*] Phase 1: Crawling website...")
    forms = crawl(target_url, session)

    print("\n[*] Phase 2: Injecting SQLi payloads...")
    for page_url, form in forms:
        test_sqli(session, page_url, form)

    print("\n[*] Phase 3: Injecting XSS payloads...")
    for page_url, form in forms:
        test_xss(session, page_url, form)

    elapsed = round(time.time() - start_time, 2)

    print(f"\n[*] Scan complete in {elapsed}s")
    print(f"[*] Total vulnerabilities found: {len(vulnerabilities)}")

    generate_report(target_url, vulnerabilities, len(forms), elapsed)

if __name__ == "__main__":
    target = input("Enter target URL (e.g. http://localhost:5000): ").strip()
    run_scanner(target)