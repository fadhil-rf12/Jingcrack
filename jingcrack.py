#!/usr/bin/python3

import os
import sys
import json
import random
import subprocess
from datetime import datetime
from argparse import ArgumentParser, Namespace
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# ─── Konfigurasi awal ─────────────────────────────────────────────────────────

RANDOM_ID = random.randint(1, 9999)
PATH_CWD = Path(os.getcwd())
DIRNAME = f"jingcrack_{RANDOM_ID}"
RESULTS_DIR = PATH_CWD / DIRNAME

# File sementara (di dalam folder output)
_TMP_TARGETS = RESULTS_DIR / f"{RANDOM_ID}_tmp_targets.txt"
_TMP_SUBFINDER = RESULTS_DIR / f"{RANDOM_ID}_tmp_subfinder.txt"
_TMP_HTTPX = RESULTS_DIR / f"{RANDOM_ID}_tmp_httpx.json"

# File output akhir
OUT_SUBDOMAIN = RESULTS_DIR / f"{RANDOM_ID}_subdomain.txt"
OUT_REPORT = RESULTS_DIR / f"{RANDOM_ID}_report.json"

FAILED_FILENAME = "NMAP_FAILED.txt"
FAILED_PATH = os.path.join(PATH_CWD, DIRNAME, FAILED_FILENAME)

# ─── Argumen CLI ──────────────────────────────────────────────────────────────

parser = ArgumentParser(
    description="JingCrack — Recon pipeline: subfinder → crt.sh → httpx → nuclei"
)
parser.add_argument(
    "-t", "--target",
    help="Domain langsung (contoh: example.com) atau path ke file berisi list domain."
)
args: Namespace = parser.parse_args()


# ─── Helper ───────────────────────────────────────────────────────────────────

def info(msg: str):
    print(f"  [*] {msg}")


def ok(msg: str):
    print(f"  [✓] {msg}")


def err(msg: str):
    print(f"  [!] {msg}")


def separator(label: str = ""):
    line = "─" * 56
    if label:
        print(f"\n  ┌{line}┐")
        pad = (56 - len(label) - 2) // 2
        print(f"  │{' ' * pad} {label} {' ' * (56 - pad - len(label) - 1)}│")
        print(f"  └{line}┘")
    else:
        print(f"  {line}")


# ─── Ambil input ──────────────────────────────────────────────────────────────

def ambil_input(target: str) -> list[str]:
    """
    Terima string target:
    - Jika path ke file → baca baris-baris domain dari file (skip baris # dan kosong)
    - Jika domain langsung → kembalikan sebagai list satu elemen
    """
    full_path = PATH_CWD / target
    if full_path.is_file():
        with open(full_path, "r", encoding="utf-8") as f:
            domains = [
                line.strip() for line in f
                if line.strip() and not line.strip().startswith("#")
            ]
        if not domains:
            err(f"File '{target}' kosong atau semua baris dikomentari.")
            sys.exit(1)
        ok(f"Memuat {len(domains)} domain dari file '{target}'")
        return domains

    # Anggap sebagai domain tunggal
    return [target.strip()]


# ─── Fase pinging ─────────────────────────────────────────────────────────────

def pinging(targets: list[str]):
    separator("FASE PINGING")
    online, offline = [], []

    for domain in targets:
        hasil = subprocess.run(
            ["ping", "-c", "3", domain],
            capture_output=True,
            text=True,
        )
        if hasil.returncode == 0:
            ok(f"{domain} → online")
            online.append(domain)
        else:
            err(f"{domain} → tampak down")
            with open(FAILED_PATH, "a") as failed:
                failed.write(hasil.stderr)
            print(f"  Detail error ada di {FAILED_PATH}")
            offline.append(domain)

    info(f"Selesai: {len(online)} online, {len(offline)} offline "
         f"dari {len(targets)} target.")
    return online, offline


# ─── Fase subfinder ───────────────────────────────────────────────────────────

def subfinder_fase(targets: list[str]) -> list[str]:
    separator("FASE SUBFINDER")
    all_subdomains: list[str] = []

    info(f"Subfinder → {", ".join(targets)}")
    if len(targets) > 1:
        _TMP_TARGETS.write_text("\n".join(targets))
        cmd = ["subfinder", "-dL", str(_TMP_TARGETS), "-recursive", "-silent"]
    else:
        cmd = ["subfinder", "-d", targets[0], "-recursive", "-silent"]

    hasil = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )
    subs = [
        line.strip() for line in hasil.stdout.splitlines()
        if line.strip()
    ]

    ok(f"Dari target: {", ".join(targets)}\n {len(subs)} subdomain ditemukan")

    all_subdomains.extend(subs)

    # Deduplikasi + sort
    all_subdomains = sorted(set(all_subdomains))

    # Simpan ke file sementara untuk httpx & nuclei
    _TMP_SUBFINDER.write_text("\n".join(all_subdomains), encoding="utf-8")

    # Simpan ke file output final
    OUT_SUBDOMAIN.write_text("\n".join(all_subdomains), encoding="utf-8")
    ok(f"Total {len(all_subdomains)} subdomain unik → {OUT_SUBDOMAIN}")

    return all_subdomains


# ─── Fase crt.sh ──────────────────────────────────────────────────────────────
def hitung_umur(tanggal_domain_lahir: str) -> int:
    tanggal_pisah = tanggal_domain_lahir.split("-")
    tahun = int(tanggal_pisah[0])

    tahun_sekarang = datetime.now().year
    umur = tahun_sekarang - tahun
    return umur


def _query_crtsh(domain: str) -> dict[str, str | None]:
    """
    Query crt.sh untuk satu domain.
    Kembalikan dict { subdomain: first_seen } dari certificate transparency logs.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        resp = requests.get(url, timeout=15, headers={
                            "Accept": "application/json",
                            "User-Agent": "Mozilla/5.0"
                            })
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.Timeout:
        err(f"crt.sh timeout untuk '{domain}'")
        return {}
    except Exception as e:
        err(f"crt.sh error untuk '{domain}': {e}")
        return {}

    seen: dict[str, str | None] = {}
    for entry in data:
        name_value = entry.get("name_value", "")
        not_before = entry.get("not_before", None)

        # name_value bisa berisi beberapa subdomain dipisah newline
        for name in name_value.splitlines():
            name = name.strip().lower().lstrip("*.")
            if not name or not name.endswith(domain):
                continue

            # Simpan tanggal terlama (first seen = paling awal)
            if name not in seen:
                seen[name] = not_before
            else:
                if not_before and (seen[name] is None or not_before < seen[name]):
                    seen[name] = not_before

    # Normalisasi format tanggal: "2021-03-14T10:00:00" → "2021-03-14"
    normalized: dict[str, str | None] = {}
    for host, ts in seen.items():
        if ts:
            normalized[host] = ts[:10]
        else:
            normalized[host] = None

    return normalized


def crtsh_fase(targets: list[str], subdomains_from_subfinder: list[str]) -> list[dict]:
    """
    Query crt.sh untuk semua domain target secara paralel.
    Gabungkan hasilnya dengan subdomain dari subfinder:
    - Subdomain dari subfinder yang ada di crt.sh → dapat first_seen
    - Subdomain dari subfinder yang tidak ada di crt.sh → first_seen: null
    - Subdomain dari crt.sh yang tidak ada di subfinder → ditambahkan
    Kembalikan list of dict { host, first_seen, source }.
    """
    separator("FASE CRT.SH")
    info(f"Query crt.sh untuk {len(targets)} domain secara paralel...")

    crtsh_map: dict[str, str | None] = {}

    with ThreadPoolExecutor(max_workers=min(len(targets), 10)) as ex:
        futures = {ex.submit(_query_crtsh, d): d for d in targets}
        for future in as_completed(futures):
            domain = futures[future]
            result = future.result()
            crtsh_map.update(result)
            ok(f"crt.sh '{domain}' → {len(result)} entri ditemukan")

    # Gabungkan dengan hasil subfinder
    subfinder_set = set(subdomains_from_subfinder)
    crtsh_set = set(crtsh_map.keys())

    combined: list[dict] = []

    # Subfinder results, diperkaya dengan first_seen dari crt.sh
    for host in sorted(subfinder_set):
        combined.append({
            "host":       host,
            "first_seen": crtsh_map.get(host),
            "age":        hitung_umur(crtsh_map[host]) if crtsh_map.get(host) else None,
            "source":     "subfinder+crtsh" if host in crtsh_set else "subfinder",
        })

    # Subdomain eksklusif dari crt.sh (tidak ditemukan subfinder)
    exclusive_crtsh = sorted(crtsh_set - subfinder_set)
    for host in exclusive_crtsh:
        combined.append({
            "host":       host,
            "first_seen": crtsh_map[host],
            "age":        hitung_umur(crtsh_map[host]) if crtsh_map.get(host) else None,
            "source":     "crtsh",
        })

    total_all = len(combined)
    total_with_date = sum(1 for e in combined if e["first_seen"])
    total_crtsh_only = len(exclusive_crtsh)

    ok(f"Total gabungan: {total_all} subdomain unik")
    ok(f"Dengan data first_seen: {total_with_date}")
    ok(f"Subdomain eksklusif dari crt.sh: {total_crtsh_only}")

    return combined


def httpx_fase() -> list[dict]:
    separator("FASE HTTPX")
    info("Menjalankan httpx...")

    hasil = subprocess.run(
        [
            "httpx",
            "-l",  str(_TMP_SUBFINDER),
            "-json",
            "-o", str(_TMP_HTTPX),
        ],
        capture_output=True,
        text=True,
    )

    if hasil.returncode != 0:
        err(f"httpx error: {hasil.stderr.strip()}")
        return []

    httpx_results: list[dict] = []
    if _TMP_HTTPX.exists():
        with open(_TMP_HTTPX, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    httpx_results.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    ok(f"httpx selesai → {len(httpx_results)} host aktif ditemukan")
    return httpx_results


# ─── Fase nuclei ──────────────────────────────────────────────────────────────

def nuclei_fase() -> list[dict]:
    separator("FASE NUCLEI")
    info("Menjalankan nuclei (mode auto-scan, severity: critical/high/medium)...")

    tmp_nuclei = RESULTS_DIR / f"{RANDOM_ID}_tmp_nuclei.txt"

    hasil = subprocess.run(
        [
            "nuclei",
            "-list",   str(_TMP_SUBFINDER),
            "-as",
            "-s",      "critical,high,medium",
            "-rl",     "50",
            "-c",      "25",
            "-o",      str(tmp_nuclei),
        ],
        capture_output=True,
        text=True,
    )

    nuclei_results: list[dict] = []

    if tmp_nuclei.exists():
        with open(tmp_nuclei, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # Nuclei output bisa berupa JSON per baris atau teks biasa
                try:
                    nuclei_results.append(json.loads(line))
                except json.JSONDecodeError:
                    nuclei_results.append({"raw": line})
        tmp_nuclei.unlink(missing_ok=True)

    ok(f"Nuclei selesai → {len(nuclei_results)} temuan")
    return nuclei_results


# ─── Bersihkan file sementara ─────────────────────────────────────────────────

def cleanup():
    for tmp in [_TMP_SUBFINDER, _TMP_HTTPX]:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


# ─── Tulis report akhir ───────────────────────────────────────────────────────

def tulis_report(
    target_input: str,
    targets: list[str],
    subdomains_enriched: list[dict],
    httpx_data: list[dict],
    nuclei_data: list[dict],
):
    report = {
        "meta": {
            "scan_id":    RANDOM_ID,
            "target":     target_input,
            "domains":    targets,
            "scan_time":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
        "subfinder": {
            "total":      len(subdomains_enriched),
            "subdomains": subdomains_enriched,
        },
        "httpx": {
            "total":   len(httpx_data),
            "results": httpx_data,
        },
        "nuclei": {
            "total":   len(nuclei_data),
            "results": nuclei_data,
        },
    }

    with open(OUT_REPORT, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    ok(f"Report lengkap → {OUT_REPORT}")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    print(f"""
  ╔══════════════════════════════════════════════════╗
  ║  JingCrack  —  Recon Pipeline                    ║
  ║  subfinder → crt.sh → httpx → nuclei             ║
  ║  Scan ID : {RANDOM_ID:<38}║
  ╚══════════════════════════════════════════════════╝
""")

    target_input = args.target
    targets = ambil_input(target_input)

    info(f"Target: {', '.join(targets)}")
    info(f"Output folder: {RESULTS_DIR}")

    # Pipeline
    target_for_subfinder = pinging(targets)
    if len(target_for_subfinder[0]) == 0:
        err("Semua target tampak down. Pipeline dihentikan.")
        sys.exit(1)
    subdomains = subfinder_fase(target_for_subfinder[0])

    if not subdomains:
        err("Tidak ada subdomain ditemukan. Pipeline dihentikan.")
        sys.exit(1)

    subdomains_enriched = crtsh_fase(targets, subdomains)

    # Update file subdomain txt dengan hasil gabungan (host saja, plain text)
    all_hosts = sorted({entry["host"] for entry in subdomains_enriched})
    OUT_SUBDOMAIN.write_text("\n".join(all_hosts), encoding="utf-8")
    _TMP_SUBFINDER.write_text("\n".join(all_hosts), encoding="utf-8")
    ok(f"File subdomain diperbarui → {len(all_hosts)} host total")

    httpx_data = httpx_fase()
    nuclei_data = nuclei_fase()

    # Tulis report & bersihkan tmp
    separator("OUTPUT")
    tulis_report(target_input, targets, subdomains_enriched,
                 httpx_data, nuclei_data)
    cleanup()

    separator()
    print(f"""
  Output tersimpan di: results/{RANDOM_ID}/
  ├── {RANDOM_ID}_subdomain.txt   (list subdomain)
  └── {RANDOM_ID}_report.json     (report lengkap)
""")


if __name__ == "__main__":
    if args.target is None:
        print("  Penggunaan: python3 jingcrack.py -t <domain|file.txt>")
        print("  Contoh   : python3 jingcrack.py -t example.com")
        sys.exit(0)

    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  [!] Proses dihentikan oleh user.")
        sys.exit(0)
