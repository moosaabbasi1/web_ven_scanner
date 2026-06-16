import os
from datetime import datetime

def generate_report(target_url, vulnerabilities, forms_scanned, elapsed):
    """Generate a plain-text vulnerability assessment report."""
    os.makedirs("report_output", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"report_output/vuln_report_{timestamp}.txt"

    with open(filename, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("   VULNERABILITY ASSESSMENT REPORT\n")
        f.write("=" * 60 + "\n\n")
        f.write(f"Target URL      : {target_url}\n")
        f.write(f"Scan Date/Time  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Forms Scanned   : {forms_scanned}\n")
        f.write(f"Scan Duration   : {elapsed} seconds\n")
        f.write(f"Total Found     : {len(vulnerabilities)}\n\n")
        f.write("-" * 60 + "\n")

        if not vulnerabilities:
            f.write("No vulnerabilities detected.\n")
        else:
            for i, v in enumerate(vulnerabilities, 1):
                f.write(f"\n[{i}] {v['type']}\n")
                f.write(f"    URL          : {v['url']}\n")
                f.write(f"    Form Action  : {v['form_action']}\n")
                f.write(f"    Field        : {v['field']}\n")
                f.write(f"    Payload Used : {v['payload']}\n")
                f.write(f"    Risk Level   : {v['risk']}\n")
                f.write(f"    Fix          : {v['recommendation']}\n")
                f.write("-" * 60 + "\n")

        f.write("\nDISCLAIMER: This tool is for educational use only.\n")

    print(f"\n[*] Report saved: {filename}")