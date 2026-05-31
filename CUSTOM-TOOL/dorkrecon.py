#!/usr/bin/python3
"""
DorkRecon - OSINT Google & GitHub Dorking Query Generator
Gunakan hanya pada domain yang kamu miliki atau sudah ada izin pengujian.
"""

import urllib.parse
import sys
import argparse

# ──────────────────────────────────────────────
# TEMPLATE DORK
# ──────────────────────────────────────────────

GOOGLE_DORKS = {
    "Subdomain & Struktur": [
        ("site:*.{domain}",
         "Semua subdomain yang terindeks"),
        ("site:{domain} -www",
         "Subdomain selain www"),
        ("site:{domain} inurl:admin",                    "Halaman admin"),
        ("site:{domain} inurl:portal",                   "Halaman portal"),
        ("site:{domain} inurl:dashboard",                "Halaman dashboard"),
        ("site:{domain} inurl:staging",
         "Environment staging"),
        ("site:{domain} inurl:dev",
         "Environment development"),
        ("site:{domain} inurl:test",
         "Environment testing"),
    ],
    "File Sensitif": [
        ("site:{domain} filetype:env",
         "File .env terekspos"),
        ("site:{domain} filetype:log",                   "File log terekspos"),
        ("site:{domain} filetype:sql",                   "File database SQL"),
        ("site:{domain} filetype:bak",                   "File backup"),
        ("site:{domain} filetype:config",                "File konfigurasi"),
        ("site:{domain} filetype:xml inurl:config",      "Konfigurasi XML"),
        ("site:{domain} filetype:json inurl:config",     "Konfigurasi JSON"),
        ("site:{domain} filetype:yaml OR filetype:yml",  "File YAML"),
        ("site:{domain} filetype:txt inurl:robots",      "robots.txt"),
        ("site:{domain} filetype:pdf",                   "Dokumen PDF publik"),
        ("site:{domain} filetype:xls OR filetype:xlsx",
         "Spreadsheet terekspos"),
        ("site:{domain} filetype:doc OR filetype:docx",
         "Dokumen Word terekspos"),
    ],
    "Login & Auth": [
        ("site:{domain} inurl:login",                    "Halaman login"),
        ("site:{domain} inurl:signin",                   "Halaman sign in"),
        ("site:{domain} inurl:register",                 "Halaman registrasi"),
        ("site:{domain} inurl:forgot-password",          "Reset password"),
        ("site:{domain} inurl:oauth",                    "Endpoint OAuth"),
        ("site:{domain} inurl:sso",                      "Single Sign-On"),
        ('site:{domain} intext:"username" intext:"password"', "Form login"),
    ],
    "Error & Info Leak": [
        ('site:{domain} intext:"error" intext:"stack trace"',
         "Stack trace terekspos"),
        ('site:{domain} intext:"sql syntax" OR intext:"mysql error"', "Error SQL"),
        ('site:{domain} intext:"warning: mysql"',        "MySQL warning"),
        ('site:{domain} intext:"php error" OR intext:"parse error"', "PHP error"),
        ('site:{domain} intext:"index of /"',
         "Directory listing terbuka"),
        ('site:{domain} intitle:"index of"',
         "Direktori terbuka (title)"),
        ('site:{domain} intext:"apache server status"',  "Apache server status"),
        ('site:{domain} intext:"phpinfo()"',             "Halaman phpinfo"),
    ],
    "API & Endpoint": [
        ("site:{domain} inurl:api",                      "Endpoint API"),
        ("site:{domain} inurl:v1 OR inurl:v2 OR inurl:v3", "Versi API"),
        ("site:{domain} inurl:swagger",                  "Swagger UI"),
        ("site:{domain} inurl:graphql",                  "Endpoint GraphQL"),
        ("site:{domain} inurl:rest",                     "REST API"),
        ("site:{domain} ext:wsdl",                       "WSDL web service"),
        ("site:{domain} inurl:api-docs",                 "Dokumentasi API"),
    ],
}

GITHUB_DORKS = {
    "Kredensial": [
        ('"{domain}" password',
         "Password mengandung domain"),
        ('"{domain}" secret_key',                        "Secret key"),
        ('"{domain}" api_key',                           "API key"),
        ('"{domain}" access_token',                      "Access token"),
        ('"{domain}" private_key',                       "Private key"),
        ('"{domain}" client_secret',                     "Client secret OAuth"),
        ('"{domain}" aws_secret',                        "AWS secret key"),
        ('"{domain}" db_password',                       "Password database"),
    ],
    "File Konfigurasi": [
        ('filename:.env "{domain}"',                     "File .env"),
        ('filename:config.yml "{domain}"',               "Konfigurasi YAML"),
        ('filename:config.json "{domain}"',              "Konfigurasi JSON"),
        ('filename:wp-config.php "{domain}"',
         "Konfigurasi WordPress"),
        ('filename:.htpasswd "{domain}"',                "File htpasswd"),
        ('filename:database.yml "{domain}"',
         "Konfigurasi database"),
        ('filename:settings.py "{domain}"',
         "Settings Django/Python"),
        ('filename:Dockerfile "{domain}"',               "Dockerfile"),
        ('filename:docker-compose.yml "{domain}"',
         "Docker Compose config"),
    ],
    "Kode Sumber": [
        ('"{domain}" extension:py',                      "Kode Python"),
        ('"{domain}" extension:js',                      "Kode JavaScript"),
        ('"{domain}" extension:php',                     "Kode PHP"),
        ('"{domain}" extension:java',                    "Kode Java"),
        ('"{domain}" extension:rb',                      "Kode Ruby"),
        ('"{domain}" "smtp" OR "mail"',
         "Konfigurasi email/SMTP"),
        ('"{domain}" "connection_string"',
         "Connection string database"),
    ],
}

# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────

RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
GRAY = "\033[90m"
RED = "\033[91m"


def colored(text, color): return f"{color}{text}{RESET}"
def bold(text): return f"{BOLD}{text}{RESET}"


def banner():
    print(colored("""
  ██████╗  ██████╗ ██████╗ ██╗  ██╗    ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔═══██╗██╔══██╗██║ ██╔╝    ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██║  ██║██║   ██║██████╔╝█████╔╝     ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██║  ██║██║   ██║██╔══██╗██╔═██╗     ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██████╔╝╚██████╔╝██║  ██║██║  ██╗    ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
""", CYAN))
    print(colored("  OSINT Google & GitHub Dorking Query Generator", GRAY))
    print(colored("  Gunakan hanya pada domain yang kamu miliki / sudah ada izin!\n", RED))


def sanitize_domain(raw: str) -> str:
    raw = raw.strip()
    for prefix in ("https://", "http://", "www."):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
    return raw.rstrip("/")


def build_google_url(query: str) -> str:
    return "https://www.google.com/search?q=" + urllib.parse.quote_plus(query)


def build_github_url(query: str) -> str:
    return "https://github.com/search?type=code&q=" + urllib.parse.quote_plus(query)


def print_section(title: str, engine: str, items: list, domain: str):
    badge = colored(f"[{engine}]", GREEN if engine == "Google" else YELLOW)
    print(f"\n  {bold(title)} {badge}")
    print("  " + "─" * 60)
    for i, (template, desc) in enumerate(items, 1):
        query = template.replace("{domain}", domain)
        url = build_google_url(
            query) if engine == "Google" else build_github_url(query)
        print(f"  {colored(str(i).rjust(2), GRAY)}. {colored(query, CYAN)}")
        print(f"      {colored('↳ ' + desc, GRAY)}")
        print(f"      {colored('🔗 ' + url, GRAY)}")


def save_to_file(domain: str, output_path: str):
    lines = []
    lines.append(f"# DorkRecon — {domain}")
    lines.append(f"# Generated by dorkrecon.py\n")

    lines.append("## GOOGLE DORKS\n")
    for cat, items in GOOGLE_DORKS.items():
        lines.append(f"### {cat}")
        for template, desc in items:
            query = template.replace("{domain}", domain)
            url = build_google_url(query)
            lines.append(f"  [{desc}]")
            lines.append(f"  Query : {query}")
            lines.append(f"  URL   : {url}\n")

    lines.append("## GITHUB DORKS\n")
    for cat, items in GITHUB_DORKS.items():
        lines.append(f"### {cat}")
        for template, desc in items:
            query = template.replace("{domain}", domain)
            url = build_github_url(query)
            lines.append(f"  [{desc}]")
            lines.append(f"  Query : {query}")
            lines.append(f"  URL   : {url}\n")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(colored(f"\n  ✔ Hasil disimpan ke: {output_path}", GREEN))


def count_dorks():
    g = sum(len(v) for v in GOOGLE_DORKS.values())
    gh = sum(len(v) for v in GITHUB_DORKS.values())
    return g, gh


# ──────────────────────────────────────────────
# ARGPARSE & MAIN
# ──────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="dorkrecon",
        description="OSINT Google & GitHub Dorking Query Generator",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Contoh penggunaan:\n"
            "  python3 dorkrecon.py -d example.com\n"
            "  python3 dorkrecon.py -d example.com --category google\n"
            "  python3 dorkrecon.py -d example.com --category github\n"
            "  python3 dorkrecon.py -d example.com --save\n"
            "  python3 dorkrecon.py -d example.com --save --output hasil.txt\n"
        )
    )
    parser.add_argument(
        "-d", "--domain",
        required=True,
        metavar="DOMAIN",
        help="Domain target, contoh: example.com"
    )
    parser.add_argument(
        "--category",
        choices=["google", "github"],
        default=None,
        metavar="ENGINE",
        help="Filter engine: google | github\n(default: tampilkan keduanya)"
    )
    parser.add_argument(
        "--save",
        action="store_true",
        help="Simpan hasil ke file .txt"
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help="Nama file output (default: dorkrecon_<domain>.txt)"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    banner()

    domain = sanitize_domain(args.domain)
    if not domain:
        print(colored("  Domain tidak boleh kosong.", RED))
        sys.exit(1)

    print(colored(f"  Domain : {domain}", CYAN))
    g_count, gh_count = count_dorks()
    print(f"  {bold('Total query:')} {g_count + gh_count}  "
          f"({colored(str(g_count) + ' Google', GREEN)}  "
          f"{colored(str(gh_count) + ' GitHub', YELLOW)})\n")

    show_google = args.category in (None, "google")
    show_github = args.category in (None, "github")

    if show_google:
        for cat, items in GOOGLE_DORKS.items():
            print_section(cat, "Google", items, domain)

    if show_github:
        for cat, items in GITHUB_DORKS.items():
            print_section(cat, "GitHub", items, domain)

    if args.save:
        filename = args.output or f"dorkrecon_{domain.replace('.', '_')}.txt"
        save_to_file(domain, filename)

    print(colored("\n  Selesai. Buka URL di atas secara manual di browser kamu.\n", GRAY))


if __name__ == "__main__":
    main()
