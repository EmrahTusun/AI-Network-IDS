# AI Network IDS - Yapay Zeka Destekli Saldırı Tespit Sistemi

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![TensorFlow](https://img.shields.io/badge/TensorFlow-2.13-FF6F00?style=flat&logo=tensorflow&logoColor=white)](https://www.tensorflow.org/)
[![Flask](https://img.shields.io/badge/Flask-2.3-000000?style=flat&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> Gerçek zamanlı ağ trafiğini analiz eden, hem kural bazlı hem de derin öğrenme tabanlı hibrit saldırı tespit sistemi.

<p align="center">
  <img src="docs/images/demo.gif" alt="Demo" width="800"/>
</p>

---

## Genel Bakış

**AI Network IDS**, ağ güvenliğinde yeni nesil bir yaklaşım sunan hibrit saldırı tespit sistemidir. Geleneksel kural bazlı yöntemler ile modern yapay zeka tekniklerini birleştirerek yüksek tespit doğruluğu ve düşük yanlış alarm oranı sağlar.

### Temel Özellikler

- **Hibrit Tespit**: Kural bazlı + LSTM derin öğrenme
- **Gerçek Zamanlı**: Saniyede ~1000 paket işleme kapasitesi
- **Modern Arayüz**: Responsive web dashboard ile canlı izleme
- **Yüksek Doğruluk**: %94-97 tespit başarı oranı
- **Kapsamlı Koruma**: 15+ farklı saldırı türü tespiti

---

## Hızlı Başlangıç

### Gereksinimler

- Python 3.8 veya üzeri
- Root/sudo yetkisi (ağ dinleme için)
- Linux tabanlı sistem (Kali Linux önerilir)

### Kurulum

```bash
# Depoyu klonla
git clone https://github.com/EmrahTusun/AI-Network-IDS.git
cd AI-Network-IDS

# Sanal ortam oluştur
python3 -m venv venv
source venv/bin/activate

# Bağımlılıkları yükle
pip install -r requirements.txt
```

### Çalıştırma

```bash
# Root yetkisiyle başlat
sudo -E python3 web/app.py
```

Tarayıcınızda açın: **http://localhost:5000**

---

## Sistem Mimarisi

```
┌─────────────────────────────────────────────────────────┐
│                    WEB DASHBOARD                        │
│          (Bootstrap + Chart.js + JavaScript)             │
└─────────────────────────────────────────────────────────┘
                          ↓ REST API
┌─────────────────────────────────────────────────────────┐
│                  FLASK BACKEND                           │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│                   IDS MOTORU                             │
│  ┌──────────────────┐        ┌──────────────────┐      │
│  │  Kural Motoru    │        │   AI Motoru      │      │
│  │  ─────────────   │        │   ────────────   │      │
│  │  • DDoS Tespit   │        │   • LSTM Model   │      │
│  │  • Port Scan     │        │   • Özellik      │      │
│  │  • Web Saldırı   │        │     Çıkarımı     │      │
│  │  • Brute Force   │        │   • Tahminleme   │      │
│  └──────────────────┘        └──────────────────┘      │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│            PAKET YAKALAMA (Scapy)                        │
└─────────────────────────────────────────────────────────┘
                          ↓
                    Ağ Trafiği
```

### Çalışma Prensibi

1. **Paket Yakalama**: Scapy ile seçilen ağ arayüzünden paketler yakalanır
2. **Akış Oluşturma**: Paketler kaynak-hedef çiftlerine göre flow'lara gruplandırılır
3. **Özellik Çıkarımı**: Her flow için 24 istatistiksel özellik hesaplanır
4. **Hibrit Analiz**:
   - Kural motoru bilinen saldırı paternlerini kontrol eder
   - AI motoru LSTM modeli ile anomali skoru hesaplar
5. **Tespit & Loglama**: Saldırı tespit edilirse veritabanına kaydedilir
6. **Görselleştirme**: Web arayüzünde gerçek zamanlı gösterilir

---

## Tespit Yetenekleri

### Kural Bazlı Tespit

| Saldırı Türü | Açıklama | Güven |
|--------------|----------|-------|
| **DDoS (SYN Flood)** | Yüksek SYN paket oranı tespiti | 100% |
| **Port Scan** | Çok sayıda porta erişim denemesi | 100% |
| **SSH Brute Force** | SSH servisine yoğun bağlantı | 95% |
| **FTP Brute Force** | FTP servisine yoğun bağlantı | 95% |
| **Telnet Brute Force** | Telnet servisine yoğun bağlantı | 92% |
| **SQL Injection** | SQL komut paternleri (HTTP) | 92% |
| **XSS** | JavaScript injection paternleri | 90% |
| **Path Traversal** | Dizin geçiş denemeleri | 90% |
| **Command Injection** | Sistem komut paternleri | 90% |
| **DNS Tunneling** | Anormal DNS sorgu yapısı | 90% |

### AI Bazlı Tespit

LSTM modeli CICIDS2017 veri seti ile eğitilmiştir ve şu saldırıları tespit eder:

- DoS/DDoS varyantları
- Web saldırıları (SQL Injection, XSS, vb.)
- Infiltration
- Botnet trafiği
- Bilinmeyen/yeni anomaliler

**Model Performansı:**
- Doğruluk: %94-97
- Kesinlik: %93-97
- Duyarlılık: %93-97
- F1-Skor: %94-97

---

## Web Arayüzü

### Ana Dashboard

<table>
  <tr>
    <td width="50%">
      <img src="docs/images/dashboard_kpi.png" alt="KPI Panel"/>
      <p align="center"><b>KPI Panel</b><br/>Toplam trafik, tespit sayısı, en tehlikeli IP</p>
    </td>
    <td width="50%">
      <img src="docs/images/live_graph.png" alt="Canlı Grafik"/>
      <p align="center"><b>Canlı Anomali Grafiği</b><br/>Gerçek zamanlı risk skoru izleme</p>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <img src="docs/images/detection_log.png" alt="Tespit Günlüğü"/>
      <p align="center"><b>Tespit Günlüğü</b><br/>Detaylı saldırı kayıtları</p>
    </td>
    <td width="50%">
      <img src="docs/images/traffic_flow.png" alt="Trafik Akışı"/>
      <p align="center"><b>Trafik İzleme</b><br/>Tüm paket akışı görüntüleme</p>
    </td>
  </tr>
</table>

### Dashboard Özellikleri

-  **Gerçek Zamanlı KPI'lar**: Toplam paket, tespit sayısı, en tehlikeli IP, baskın saldırı türü
-  **Canlı Grafik**: Anomali skorunun saniye saniye görselleştirilmesi
-  **Tespit Günlüğü**: Son 20 saldırının detaylı listesi
-  **Trafik İzleme**: Tüm ağ trafiğinin protokol bazlı gösterimi
-  **Kontrol Paneli**: Sistem başlatma/durdurma, arayüz seçimi, log temizleme

---

## Teknoloji Yığını

### Backend

| Teknoloji | Versiyon | Kullanım Alanı |
|-----------|----------|----------------|
| **Python** | 3.8+ | Ana programlama dili |
| **Flask** | 2.3 | Web framework & REST API |
| **Scapy** | 2.5 | Paket yakalama ve analiz |
| **TensorFlow** | 2.13 | Derin öğrenme modeli |
| **Keras** | (TensorFlow içinde) | LSTM model oluşturma |
| **NumPy** | 1.24 | Sayısal hesaplamalar |
| **Pandas** | 2.0 | Veri işleme |
| **Scikit-learn** | 1.3 | Veri normalizasyonu |
| **SQLite** | 3 | Log veritabanı |
| **Joblib** | 1.3 | Model serileştirme |

### Frontend

| Teknoloji | Kullanım Alanı |
|-----------|----------------|
| **HTML5/CSS3** | Temel yapı |
| **Bootstrap 5** | Responsive tasarım framework |
| **JavaScript (ES6)** | İstemci tarafı mantık |
| **Chart.js** | Gerçek zamanlı grafik çizimi |
| **Font Awesome** | İkon kütüphanesi |

### Machine Learning

- **Model Tipi**: LSTM (Long Short-Term Memory)
- **Eğitim Veri Seti**: CICIDS2017
- **Özellik Sayısı**: 24 akış bazlı istatistiksel özellik
- **Normalizasyon**: StandardScaler
- **Etiket Kodlama**: LabelEncoder (multiclass için)

---

## Proje Yapısı

```
AI-Network-IDS/
│
├── web/                          # Web uygulaması
│   ├── app.py                    # Flask ana dosyası
│   ├── templates/
│   │   └── index.html            # Dashboard HTML
│   └── static/                   # CSS, JS, görseller (gelecek)
│
├── src/                          # Kaynak kodlar
│   ├── __init__.py
│   ├── ids_engine.py             # IDS ana motoru
│   ├── feature_extractor.py      # Akış istatistik hesaplayıcı
│   └── modules/
│       ├── __init__.py
│       └── database.py           # SQLite veritabanı yönetimi
│
├── models/                       # Eğitilmiş modeller
│   ├── trafik_uzman.h5           # LSTM model dosyası
│   ├── uzman_scaler.pkl          # StandardScaler
│   ├── uzman_encoder.pkl         # LabelEncoder
│   └── README.md                 # Model bilgileri
│
├── data/                         # Veri dosyaları
│   ├── security_logs.db          # SQLite log veritabanı
│   └── README.md                 # Veri seti bilgileri
│
├── docs/                         # Dokümantasyon
│   ├── images/                   # Ekran görüntüleri
│   ├── installation.md           # Kurulum kılavuzu
│   ├── usage.md                  # Kullanım kılavuzu
│   └── api.md                    # API referansı
│
├── tests/                        # Test dosyaları
│   └── test_ids_engine.py        # Birim testleri
│
├── config.py                     # Sistem konfigürasyonu
├── requirements.txt              # Python bağımlılıkları
├── README.md                     # Bu dosya
├── LICENSE                       # MIT Lisansı
└── .gitignore                    # Git ignore kuralları
```

---

## ⚙️ Konfigürasyon

`config.py` dosyasından sistem ayarları yapılabilir:

```python
# Veritabanı
DB_PATH = "data/security_logs.db"

# Model dosyaları
MODEL_PATH = "models/trafik_uzman.h5"
SCALER_PATH = "models/uzman_scaler.pkl"
ENCODER_PATH = "models/uzman_encoder.pkl"

# IDS ayarları
FLOW_TIMEOUT = 15                # Flow timeout süresi (saniye)
AI_ANALYSIS_INTERVAL = 15        # Her kaç pakette bir AI analizi
DETECTION_THRESHOLD = 0.90       # AI tespit eşiği (0-1)

# Web sunucu
WEB_HOST = "0.0.0.0"            # Tüm network interface'lerden erişim
WEB_PORT = 5000                  # Port numarası
DEBUG = False                    # Production modunda False
```

---

## Kullanım Kılavuzu

### 1. Sistemi Başlatma

```bash
# Root yetkisiyle başlat (ağ dinleme için gerekli)
sudo -E python3 web/app.py

# -E parametresi: virtual environment'ı korur
```

### 2. Web Arayüzünde İşlemler

**Adım 1:** Tarayıcıda `http://localhost:5000` adresine git

**Adım 2:** Ağ arayüzü seç
- Dropdown menüden izlemek istediğin interface'i seç (eth0, wlan0, vb.)

**Adım 3:** Başlat butonuna tıkla
- Sistem paket yakalamaya başlar
- Dashboard canlı güncellenir

**Adım 4:** İzleme
- KPI panelinden genel durumu gör
- Grafikte anomali skorunu takip et
- Tespit günlüğünde detaylı saldırı bilgilerini incele
- Trafik akışında tüm paketleri gör

**Adım 5:** Durdur
- İşlem bittiğinde "Durdur" butonuna bas
- Loglar veritabanında saklanır

### 3. Log Yönetimi

**Logları Görüntüleme:**
- Web arayüzünde "Tespit Günlüğü" tablosu
- Son 20 tespit otomatik gösterilir

**Logları Temizleme:**
- Sağ üst köşedeki çöp kutusu ikonuna tıkla
- Tüm loglar ve sayaçlar sıfırlanır

**Logları Dışa Aktarma:**
```bash
# SQLite veritabanından CSV'ye çevirme
sqlite3 data/security_logs.db
.mode csv
.output exports/logs.csv
SELECT * FROM trafik_loglari;
.quit
```

---

## Test ve Doğrulama

### Sistemin Testleri

**1. Port Scan Tespiti:**
```bash
# Nmap ile port tarama
nmap -sS -p 1-100 [hedef_ip]

# Sistem "Port Scan" olarak tespit etmeli
```

**2. HTTP Saldırı Tespiti:**
```bash
# SQL Injection denemesi (test ortamında)
curl "http://test-site.local/login?user=admin' OR '1'='1"

# Sistem "SQL Injection Şüphesi" tespit etmeli
```

**3. DNS Tunneling Tespiti:**
```bash
# Uzun DNS sorgusu
dig aaaaaabbbbbbccccccddddddeeeeeeffffffffgggggggg.example.com

# Sistem "DNS Tunneling Şüphesi" tespit etmeli
```

**4. DDoS Simülasyonu:**
```bash
# hping3 ile SYN flood
hping3 -S --flood -p 80 [hedef_ip]

# Sistem "DDoS (SYN Flood)" tespit etmeli
```

### Performans Testleri

**Yük Testi:**
```bash
# 10 dakika yoğun trafik
# Tcpreplay ile PCAP replay
tcpreplay -i eth0 -K --mbps=10 test_traffic.pcap

# İzlenecek metrikler:
# - CPU kullanımı <%60 kalmalı
# - RAM kullanımı <500MB olmalı
# - Paket kaybı olmamalı
```

---

## Performans Metrikleri

### Model Performansı (CICIDS2017 Test Seti)

| Metrik | Binary | Multiclass |
|--------|--------|------------|
| **Accuracy** | 97.5% | 94.2% |
| **Precision** | 96.8% | 93.5% |
| **Recall** | 97.2% | 93.8% |
| **F1-Score** | 97.0% | 94.0% |
| **AUC-ROC** | 0.98 | - |

### Sistem Performansı (Gerçek Ortam)

| Metrik | Değer |
|--------|-------|
| **Paket İşleme Hızı** | ~1000 paket/saniye |
| **AI Tahmin Süresi** | ~50ms/flow |
| **Veritabanı Yazma** | <5ms |
| **Web Gecikme** | <100ms |
| **CPU Kullanımı (idle)** | %5-10 |
| **CPU Kullanımı (yük)** | %40-60 |
| **RAM Kullanımı** | 300-500 MB |
| **Yanlış Pozitif Oranı** | ~2-3% |

---

## Güvenlik Notları

### Gerekli Yetkiler

Sistem, **ağ dinleme** için root yetkisi gerektirir:
-  `sudo -E python3 web/app.py` ile başlatın
-  Normal kullanıcı yetkisiyle çalışmaz

### Gizlilik

- Sistem **sadece metadata** analiz eder (IP, port, protokol, paket boyutu)
- **HTTPS trafiğinin içeriği** (TLS şifreli) okunamaz ve okunmaz
- **Plaintext HTTP** trafiğinde payload analizi yapılır (web saldırıları için)

### Production Kullanımı

Production ortamında kullanırken:
1. `config.py`'de `DEBUG = False` yapın
2. Web arayüzüne erişimi firewall ile kısıtlayın
3. Düzenli log temizliği yapın (veritabanı şişmesini önlemek için)
4. HTTPS kullanın (self-signed sertifika yeterli)

---

## Bilinen Sınırlamalar

### HTTPS İçerik Analizi
- **Sorun**: TLS şifrelemesi nedeniyle HTTPS payload okunamıyor
- **Çözüm**: HTTPS trafiği için davranışsal analiz (akış özellikleri, AI motoru)

### Yüksek Hızlı Ağlar
- **Sorun**: 10Gbps+ ağlarda paket kaybı olabilir
- **Çözüm**: Gelecek sürümlerde dağıtık mimari planlanıyor

### Model Güncellemesi
- **Sorun**: Yeni saldırı türleri için model yeniden eğitilmeli
- **Çözüm**: Periyodik model güncelleme mekanizması geliştirilecek

---

## Gelecek Planlar

### Kısa Vadeli (1-3 Ay)
- [ ] Docker container desteği
- [ ] Otomatik model güncelleme
- [ ] Daha fazla test senaryosu
- [ ] API dokümantasyonu

### Orta Vadeli (3-6 Ay)
- [ ] SIEM entegrasyonu (Splunk, ELK)
- [ ] Otomatik firewall kuralı oluşturma
- [ ] E-posta/SMS alarm sistemi
- [ ] Threat intelligence entegrasyonu

### Uzun Vadeli (6+ Ay)
- [ ] Dağıtık mimari (Kafka, Redis)
- [ ] Mobil uygulama
- [ ] Makine öğrenmesi model çeşitliliği
- [ ] Cloud deployment (AWS/Azure/GCP)

---

## Katkıda Bulunma

Katkılarınızı bekliyoruz! Lütfen şu adımları izleyin:

1. Projeyi fork edin
2. Feature branch oluşturun (`git checkout -b feature/yeniOzellik`)
3. Değişikliklerinizi commit edin (`git commit -m 'Yeni özellik: XYZ'`)
4. Branch'inizi push edin (`git push origin feature/yeniOzellik`)
5. Pull Request açın

### Geliştirme Kuralları

- Kod yorumları **Türkçe** olmalı
- PEP 8 standartlarına uyulmalı
- Yeni özellikler test edilmeli
- Dokümantasyon güncellenmelidir

---

## Lisans

Bu proje [MIT Lisansı](LICENSE) altında lisanslanmıştır.

```
MIT License

Copyright (c) 2026 Emrah Tuşun

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction...
```

---

## Yazar

**Emrah Tuşun**

Bilgisayar Mühendisliği Bitirme Projesi  
[Üniversite Adı], 2026

 E-posta: [email@example.com]  
 GitHub: [@EmrahTusun](https://github.com/EmrahTusun)  
 LinkedIn: [linkedin.com/in/emrah-tusun](https://linkedin.com/in/emrah-tusun)

---

## Referanslar ve Kaynaklar

### Akademik Makaleler

1. Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization." *ICISSP*.

2. Vinayakumar, R. et al. (2019). "Deep Learning Approach for Intelligent Intrusion Detection System." *IEEE Access*.

3. Kim, J. et al. (2020). "Method of intrusion detection using deep neural network." *IEEE BigComp*.

### Veri Setleri

- **CICIDS2017**: https://www.unb.ca/cic/datasets/ids-2017.html
- **NSL-KDD**: https://www.unb.ca/cic/datasets/nsl.html

### Dokümantasyon

- **Scapy**: https://scapy.readthedocs.io/
- **TensorFlow**: https://www.tensorflow.org/
- **Flask**: https://flask.palletsprojects.com/
- **Scikit-learn**: https://scikit-learn.org/

---

<p align="center">
  <b>⭐ Projeyi beğendiyseniz yıldız vermeyi unutmayın!</b>
</p>

<p align="center">
  Made with and by Emrah Tuşun
</p>
