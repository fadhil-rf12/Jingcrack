# JingCrack - Network Reconnaissance Pipeline

JingCrack adalah tool otomatis untuk melakukan reconnaissance pada target domain dengan menggabungkan tiga tahap scanning: subfinder (enumerasi subdomain), httpx (deteksi host aktif), dan nuclei (vulnerability scanning).

## Fitur Utama

- Subfinder Integration: Enumerasi subdomain secara rekursif dari domain target
- HTTP Detection: Identifikasi host aktif dengan httpx
- Vulnerability Scanning: Deteksi vulnerability kritis dan high-risk dengan nuclei
- Auto Organization: Semua output disimpan dalam folder terstruktur dengan ID random unik
- Clean Output: Dua file output terakhir (list subdomain + report lengkap JSON)
- Error Handling: Penanganan error yang proper di setiap fase

## Prasyarat

Pastikan sudah menginstall dependencies berikut:

1. Python 3.7+
2. subfinder
3. httpx
4. nuclei

### Instalasi Dependencies (Linux/macOS)

```bash
# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# HTTPX
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Pastikan semua tools sudah ada di PATH sistem Anda.

## Penggunaan

### Syntax Dasar

```bash
python3 jingcrack.py -t <target>
```

### Parameter

- `-t`, `--target`: Target scanning. Bisa berupa:
  - Domain langsung: `example.com`
  - File berisi list domain: `domains.txt` (satu domain per baris, abaikan baris dengan # dan baris kosong)

### Contoh Penggunaan

Scan single domain:
```bash
python3 jingcrack.py -t google.com
```

Scan dari file:
```bash
python3 jingcrack.py -t targets.txt
```

File targets.txt format:
```
# Domain untuk testing
google.com
github.com
example.com
# Lebih banyak domain di bawah
api.example.com
```

## Pipeline Scanning

### 1. Fase Pinging
Cek ketersediaan target dengan ping (3 paket). Mencatat mana yang online dan mana yang offline.

### 2. Fase Subfinder
Melakukan enumerasi subdomain rekursif untuk setiap domain target menggunakan subfinder dengan flag `-recursive -silent`. Hasil subdomain dikumpulkan, didedulikasi, dan diurutkan.

### 3. Fase HTTPX
Melakukan probe terhadap semua subdomain yang ditemukan untuk mengidentifikasi:
- Status HTTP/HTTPS
- Header response
- Informasi host aktif

Output dalam format JSON per baris.

### 4. Fase Nuclei
Menjalankan vulnerability scanning dengan konfigurasi:
- Mode: auto-scan (`-as`)
- Severity: critical, high, medium
- Rate limit: 50 req/detik
- Concurrency: 25 thread

## Output

Semua output disimpan dalam struktur folder:

```
results/
└── <RANDOM_ID>/
    ├── <RANDOM_ID>_subdomain.txt    (List semua subdomain ditemukan)
    └── <RANDOM_ID>_report.json      (Report lengkap dalam JSON)
```

Contoh struktur folder:
```
results/
└── 4821/
    ├── 4821_subdomain.txt
    └── 4821_report.json
```

### Format File Output

#### 1. File Subdomain (*.txt)

Plain text berisi satu subdomain per baris:
```
api.example.com
app.example.com
cdn.example.com
mail.example.com
```

#### 2. Report JSON (*.json)

Struktur JSON lengkap dengan semua hasil scanning:

```json
{
  "meta": {
    "scan_id": 4821,
    "target": "example.com",
    "domains": ["example.com"],
    "scan_time": "2025-01-15 14:30:45"
  },
  "subfinder": {
    "total": 150,
    "subdomains": [
      "api.example.com",
      "app.example.com",
      ...
    ]
  },
  "httpx": {
    "total": 45,
    "results": [
      {
        "url": "https://api.example.com",
        "status_code": 200,
        "content_length": 1024,
        ...
      },
      ...
    ]
  },
  "nuclei": {
    "total": 12,
    "results": [
      {
        "template": "ssl-expired",
        "type": "ssl",
        "severity": "high",
        ...
      },
      ...
    ]
  }
}
```

## Penjelasan Istilah

- **Subdomain**: Domain yang merupakan bagian dari domain utama (contoh: api.google.com adalah subdomain dari google.com)
- **HTTP Probe**: Pengiriman request HTTP/HTTPS ke sebuah host untuk mengecek status dan respons
- **Vulnerability Scanning**: Proses mencari kerentanan keamanan pada aplikasi/infrastruktur target
- **Severity Level**: Tingkat keparahan vulnerability (critical > high > medium > low)

## Fitur Tambahan

### Paging dan Logging
Setiap scanning akan menampilkan progress dengan format output yang rapi:
```
  [*] Info message
  [✓] Success message
  [!] Error message
```

### Auto Cleanup
File sementara yang dibuat selama proses scanning akan otomatis dihapus setelah report final digenerate.

### Deduplikasi
Subdomain yang ditemukan dari multiple sources akan otomatis didedulikasi dan diurutkan secara alfabetis.

## Troubleshooting

### Error: "subfinder tidak ditemukan"
Solusi:
```bash
which subfinder
# Jika tidak ditemukan, install ulang
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
export PATH=$PATH:$(go env GOPATH)/bin
```

### Error: "httpx error"
Kemungkinan penyebab:
- File input subdomain tidak ada atau kosong
- httpx belum terinstall dengan benar
- Permissions masalah pada folder results

### Error: "nuclei gagal"
Kemungkinan penyebab:
- Nuclei templates belum diupdate
- Memori insufficient untuk scanning besar-besaran
- Rate limit terlalu tinggi untuk infrastruktur target

Solusi update nuclei templates:
```bash
nuclei -update-templates
```

## Catatan Penting

1. Selalu dapatkan izin sebelum melakukan scanning pada domain yang bukan milik Anda
2. Scanning pada infrastruktur orang lain tanpa izin dapat melanggar hukum
3. Tool ini dirancang untuk penetration testing yang sah dan authorized
4. Gunakan secara bertanggung jawab dan etis

## Performance Tips

- Untuk scanning besar (100+ subdomain), pastikan memory cukup
- Nuclei rate limit dapat disesuaikan sesuai kemampuan target
- Jalankan pada server/VPS jika scanning dari laptop lokal untuk hasil lebih stabil

## Changelog

### v1.0
- Initial release
- Support untuk single domain dan multiple domains dari file
- Output terstruktur dengan ID random
- Error handling comprehensive

## License

Open source untuk keperluan penetration testing yang sah dan authorized.

## Support

Untuk issue atau pertanyaan, silakan hubungi developer atau buat issue di repository.

---

JingCrack - Jumping Around Scanning Tool
Version 1.0