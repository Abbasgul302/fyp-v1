import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import argparse


SECURITY_HEADERS = {
    "Strict-Transport-Security":
        "HSTS is missing",
    "Content-Security-Policy":
        "Content Security Policy is missing",
    "X-Content-Type-Options":
        "X-Content-Type-Options is missing",
    "X-Frame-Options":
        "X-Frame-Options is missing"
}


def check_headers(response):
    print("\n[+] Security Headers")

    for header, message in SECURITY_HEADERS.items():
        if header in response.headers:
            print(f"    [OK] {header}")
        else:
            print(f"    [!] {message}")


def check_cookies(response):
    print("\n[+] Cookie Security")

    cookies = response.cookies

    if not cookies:
        print("    [INFO] No cookies found")
        return

    for cookie in cookies:
        print(f"    Cookie: {cookie.name}")

        if cookie.secure:
            print("        [OK] Secure")
        else:
            print("        [!] Secure flag missing")

        if "HttpOnly" in cookie._rest.get("HttpOnly", ""):
            print("        [OK] HttpOnly")
        else:
            print("        [!] HttpOnly may be missing")


def find_links(url, response):
    print("\n[+] Links Found")

    soup = BeautifulSoup(response.text, "html.parser")

    links = set()

    for tag in soup.find_all("a", href=True):
        link = urljoin(url, tag["href"])

        if urlparse(link).netloc == urlparse(url).netloc:
            links.add(link)

    for link in sorted(links):
        print(f"    {link}")

    print(f"\n    Total internal links: {len(links)}")


def scan(url):
    print("=" * 60)
    print("        WebVulnScanner V1")
    print("=" * 60)

    print(f"\n[*] Target: {url}")

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

    except requests.RequestException as error:
        print(f"\n[!] Connection error: {error}")
        return

    print(f"\n[+] Final URL: {response.url}")
    print(f"[+] Status Code: {response.status_code}")
    print(f"[+] Server: {response.headers.get('Server', 'Not disclosed')}")
    print(f"[+] Content-Type: {response.headers.get('Content-Type', 'Unknown')}")

    check_headers(response)
    check_cookies(response)
    find_links(url, response)


def main():
    parser = argparse.ArgumentParser(
        description="Basic Web Vulnerability Scanner V1"
    )

    parser.add_argument(
        "url",
        help="Authorized target URL"
    )

    args = parser.parse_args()

    scan(args.url)


if __name__ == "__main__":
    main()

