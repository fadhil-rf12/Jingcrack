# JingCrack - Network Reconnaissance Pipeline

JingCrack adalah tool otomatis untuk melakukan reconnaissance pada target domain dengan menggabungkan empat tahap scanning: subfinder (enumerasi subdomain), crt.sh (domain age checking), httpx (deteksi host aktif), dan nuclei (vulnerability scanning).

## Fitur Utama

- Subfinder Integration: Enumerasi subdomain secara rekursif dari domain target, mendukung single domain (-d) dan multiple domain dari file (-dL)
- Domain Age Checking: Pemeriksaan tanggal pertama kali subdomain muncul di Certificate Transparency Logs via crt.sh, termasuk perhitungan umur domain dalam tahun
- HTTP Detection: Identifikasi host aktif dengan httpx
- Vulnerability Scanning: Deteksi vulnerability kritis dan high-risk dengan nuclei
- Auto Organization: Semua output disimpan dalam folder terstruktur dengan ID random unik
- Clean Output: Dua file output akhir (list subdomain + report lengkap JSON)
- Error Handling: Penanganan error yang proper di setiap fase

## Prasyarat

Pastikan sudah menginstall dependencies berikut:

1. Python 3.12+
2. Python library: `requests`
3. subfinder
4. httpx
5. nuclei

### Instalasi Dependencies (Linux/macOS)

```bash
# Python library
pip install requests

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

Format file targets.txt:
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
Cek ketersediaan target dengan ping (3 paket). Mencatat mana yang online dan mana yang offline. Hanya domain yang online yang akan dilanjutkan ke fase subfinder. Detail error domain yang down disimpan ke file `NMAP_FAILED.txt` di dalam folder output.

### 2. Fase Subfinder
Melakukan enumerasi subdomain rekursif untuk domain target yang terdeteksi online. Jika input berupa single domain, menggunakan flag `-d`. Jika input berupa file berisi banyak domain, subfinder langsung membaca file tersebut menggunakan flag `-dL` tanpa loop per domain. Hasil subdomain dikumpulkan, dideduplikasi, dan diurutkan.

### 3. Fase crt.sh (Domain Age Checking)
Melakukan query ke Certificate Transparency Logs via crt.sh untuk setiap domain target secara paralel. Hasilnya digabungkan dengan subdomain dari subfinder:

- Subdomain dari subfinder yang ada di crt.sh: mendapat data `first_seen` dan `age`
- Subdomain dari subfinder yang tidak ada di crt.sh: `first_seen` dan `age` bernilai null
- Subdomain eksklusif dari crt.sh yang tidak ditemukan subfinder: tetap ditambahkan ke list

### 4. Fase HTTPX
Melakukan probe terhadap semua subdomain yang ditemukan untuk mengidentifikasi:
- Status HTTP/HTTPS
- Header response
- Informasi host aktif

Output dalam format JSON per baris.

### 5. Fase Nuclei
Menjalankan vulnerability scanning dengan konfigurasi:
- Mode: auto-scan (`-as`)
- Severity: critical, high, medium
- Rate limit: 50 req/detik
- Concurrency: 25 thread

## Output

Semua output disimpan dalam struktur folder:

```
results/
└── jingcrack_<RANDOM_ID>/
    ├── <RANDOM_ID>_subdomain.txt    (List semua subdomain ditemukan)
    ├── <RANDOM_ID>_report.json      (Report lengkap dalam JSON)
    └── NMAP_FAILED.txt              (Detail error domain yang down, jika ada)
```

Contoh struktur folder:
```
results/
└── jingcrack_4821/
    ├── 4821_subdomain.txt
    ├── 4821_report.json
    └── NMAP_FAILED.txt
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
      {
        "host": "api.example.com",
        "first_seen": "2019-07-02",
        "age": 5,
        "source": "subfinder+crtsh"
      },
      {
        "host": "cdn.example.com",
        "first_seen": null,
        "age": null,
        "source": "subfinder"
      },
      {
        "host": "old.example.com",
        "first_seen": "2017-01-15",
        "age": 8,
        "source": "crtsh"
      }
    ]
  },
  "httpx": {
    "total": 45,
    "results": [
      {
        "url": "https://api.example.com",
        "status_code": 200,
        "content_length": 1024
      }
    ]
  },
  "nuclei": {
    "total": 12,
    "results": [
      {
        "template": "ssl-expired",
        "type": "ssl",
        "severity": "high"
      }
    ]
  }
}
```

### Penjelasan Field Subdomain

| Field | Tipe | Keterangan |
|---|---|---|
| `host` | string | Nama subdomain |
| `first_seen` | string / null | Tanggal pertama kali muncul di Certificate Transparency Logs (format: YYYY-MM-DD) |
| `age` | integer / null | Umur subdomain dalam tahun dihitung dari `first_seen` |
| `source` | string | Asal data: `subfinder+crtsh`, `subfinder`, atau `crtsh` |

## Penjelasan Istilah

- **Subdomain**: Domain yang merupakan bagian dari domain utama (contoh: api.google.com adalah subdomain dari google.com)
- **Certificate Transparency Logs**: Sistem pencatatan publik yang menyimpan semua SSL certificate yang pernah diterbitkan, digunakan crt.sh untuk melacak kapan sebuah subdomain pertama kali memiliki sertifikat SSL
- **HTTP Probe**: Pengiriman request HTTP/HTTPS ke sebuah host untuk mengecek status dan respons
- **Vulnerability Scanning**: Proses mencari kerentanan keamanan pada aplikasi/infrastruktur target
- **Severity Level**: Tingkat keparahan vulnerability (critical > high > medium > low)

## Fitur Tambahan

### Progress Logging
Setiap scanning akan menampilkan progress dengan format output yang rapi:
```
  [*] Info message
  [✓] Success message
  [!] Error message
```

### Auto Cleanup
File sementara yang dibuat selama proses scanning akan otomatis dihapus setelah report final digenerate.

### Deduplikasi
Subdomain yang ditemukan dari subfinder maupun crt.sh akan otomatis dideduplikasi dan diurutkan secara alfabetis.

### Paralel crt.sh Query
Query ke crt.sh untuk setiap domain target dijalankan secara paralel menggunakan ThreadPoolExecutor, sehingga lebih efisien untuk input banyak domain.

## Troubleshooting

### Error: "subfinder tidak ditemukan"
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
- Permissions bermasalah pada folder results

### Error: "nuclei gagal"
Kemungkinan penyebab:
- Nuclei templates belum diupdate
- Memori tidak cukup untuk scanning besar
- Rate limit terlalu tinggi untuk infrastruktur target

Solusi update nuclei templates:
```bash
nuclei -update-templates
```

### crt.sh timeout
crt.sh kadang lambat untuk domain besar. Timeout default adalah 15 detik per domain. Jika sering timeout, coba jalankan ulang — hasil subfinder tetap tersimpan dan pipeline tetap berlanjut meski crt.sh gagal untuk sebagian domain.

## Catatan Penting

1. Selalu dapatkan izin sebelum melakukan scanning pada domain yang bukan milik Anda
2. Scanning pada infrastruktur orang lain tanpa izin dapat melanggar hukum
3. Tool ini dirancang untuk penetration testing yang sah dan authorized
4. Gunakan secara bertanggung jawab dan etis

## Performance Tips

- Untuk scanning besar (100+ subdomain), pastikan memory cukup
- Nilai `-rl` dan `-c` pada nuclei dapat disesuaikan dengan kemampuan jaringan dan target
- Jalankan pada server/VPS untuk hasil lebih stabil dibanding laptop lokal

## Changelog

### v1.1
- Tambah fase crt.sh untuk domain age checking
- Format subdomain di report JSON berubah dari array of string menjadi array of object (host, first_seen, age, source)
- Subfinder sekarang menggunakan -dL untuk input file (lebih efisien, tanpa loop per domain)
- Query crt.sh dijalankan paralel dengan ThreadPoolExecutor
- Tambah field `age` (umur domain dalam tahun) di setiap entri subdomain
- Perbaikan bug: mode "w" pada NMAP_FAILED.txt diganti "a" agar tidak overwrite
- Perbaikan bug: pengecekan hasil pinging yang salah tipe data
- Nama folder output berubah dari `<ID>` menjadi `jingcrack_<ID>`

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
Version 1.1