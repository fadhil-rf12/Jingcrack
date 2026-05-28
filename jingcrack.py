#!/usr/bin/python3

import os
import sys
import json
import random
import subprocess
from datetime import datetime
from argparse import ArgumentParser, Namespace
from pathlib import Path

# ─── Konfigurasi awal ─────────────────────────────────────────────────────────

RANDOM_ID = random.randint(1, 9999)
PATH_CWD = Path(os.getcwd())
DIRNAME = f"jingcrack_{str(RANDOM_ID)}"

RESULTS_DIR = PATH_CWD / DIRNAME

# File sementara (di dalam folder output)
_TMP_SUBFINDER = RESULTS_DIR / f"{RANDOM_ID}_tmp_subfinder.txt"
_TMP_HTTPX = RESULTS_DIR / f"{RANDOM_ID}_tmp_httpx.json"

# File output akhir
OUT_SUBDOMAIN = RESULTS_DIR / f"{RANDOM_ID}_subdomain.txt"
OUT_REPORT = RESULTS_DIR / f"{RANDOM_ID}_report.json"

FAILED_FILENAME = "NMAP_FAILED.txt"
FAILED_PATH = os.path.join(PATH_CWD, DIRNAME, FAILED_FILENAME)

# ─── Argumen CLI ──────────────────────────────────────────────────────────────

parser = ArgumentParser(
    description="Jingcrack — Recon pipeline: subfinder → httpx → nuclei"
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
            with open(FAILED_PATH, "w") as failed:
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

    for domain in targets:
        info(f"Subfinder → {domain}")
        hasil = subprocess.run(
            ["subfinder", "-d", domain, "-recursive", "-silent"],
            capture_output=True,
            text=True,
        )
        if hasil.returncode != 0 and not hasil.stdout.strip():
            err(f"Subfinder gagal untuk '{domain}': {hasil.stderr.strip()}")
            continue

        subs = [
            line.strip() for line in hasil.stdout.splitlines()
            if line.strip()
        ]
        ok(f"{domain} → {len(subs)} subdomain ditemukan")
        all_subdomains.extend(subs)

    # Deduplikasi + sort
    all_subdomains = sorted(set(all_subdomains))

    # Simpan ke file sementara untuk httpx & nuclei
    _TMP_SUBFINDER.write_text("\n".join(all_subdomains), encoding="utf-8")

    # Simpan ke file output final
    OUT_SUBDOMAIN.write_text("\n".join(all_subdomains), encoding="utf-8")
    ok(f"Total {len(all_subdomains)} subdomain unik → {OUT_SUBDOMAIN}")

    return all_subdomains


# ─── Fase httpx ───────────────────────────────────────────────────────────────

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
    subdomains: list[str],
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
            "total":      len(subdomains),
            "subdomains": subdomains,
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
  ║  jingcrack Again  —  Recon Pipeline                 ║
  ║  subfinder → httpx → nuclei                      ║
  ║  Scan ID : {RANDOM_ID:<38}║
  ╚══════════════════════════════════════════════════╝
""")

    target_input = args.target
    targets = ambil_input(target_input)

    info(f"Target: {', '.join(targets)}")
    info(f"Output folder: results/{RANDOM_ID}/\n")

    # Pipeline
    ping = pinging(targets)
    subdomains = subfinder_fase(ping[0])

    if not subdomains:
        err("Tidak ada subdomain ditemukan. Pipeline dihentikan.")
        sys.exit(1)

    httpx_data = httpx_fase()
    nuclei_data = nuclei_fase()

    # Tulis report & bersihkan tmp
    separator("OUTPUT")
    tulis_report(target_input, targets, subdomains, httpx_data, nuclei_data)
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
        os.makedirs(DIRNAME)
        main()
    except KeyboardInterrupt:
        print("\n\n  [!] Proses dihentikan oleh user.")
        sys.exit(0)
