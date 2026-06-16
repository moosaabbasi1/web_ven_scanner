import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def crawl(url, session, max_pages=10):
    visited = set()
    to_visit = [url]
    forms_found = []
    headers = {"User-Agent": "VulnScanner/1.0 (Educational Use Only)"}

    while to_visit and len(visited) < max_pages:
        current_url = to_visit.pop(0)
        if current_url in visited:
            continue
        try:
            response = session.get(current_url, headers=headers, timeout=10)
            visited.add(current_url)
            soup = BeautifulSoup(response.text, "html.parser")

            for form in soup.find_all("form"):
                form_data = get_form_details(form, current_url)
                forms_found.append((current_url, form_data))

            base_domain = urlparse(url).netloc
            for link in soup.find_all("a", href=True):
                full_link = urljoin(current_url, link["href"])
                if urlparse(full_link).netloc == base_domain:
                    if full_link not in visited:
                        to_visit.append(full_link)

        except Exception as e:
            print(f"  [!] Error crawling {current_url}: {e}")

    print(f"  [*] Crawled {len(visited)} page(s), found {len(forms_found)} form(s).")
    return forms_found


def get_form_details(form, page_url):
    details = {}
    action = form.attrs.get("action", "")
    details["action"] = urljoin(page_url, action)
    details["method"] = form.attrs.get("method", "get").lower()
    details["inputs"] = []

    for input_tag in form.find_all(["input", "textarea", "select"]):
        input_name = input_tag.attrs.get("name")
        input_type = input_tag.attrs.get("type", "text")
        input_value = input_tag.attrs.get("value", "test")
        if input_name:
            details["inputs"].append({
                "name": input_name,
                "type": input_type,
                "value": input_value
            })

    return details