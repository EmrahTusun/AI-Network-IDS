import os
import time
import re
from collections import deque
from typing import Dict, Optional, Tuple, Any, List

from scapy.all import AsyncSniffer, IP, TCP, UDP, DNS, Raw

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
import numpy as np
import joblib

try:
    import tensorflow as tf
except Exception:
    tf = None

from src.moduller.veritabani_yoneticisi import VeritabaniYoneticisi
from src.oznitelik_hesaplayici import AkisIstatistikcisi


class IDSMotoru:
    """
    Hibrit IDS:
      - Kural Motoru: Port scan, SYN flood, brute-force paterni, DNS tunneling, plaintext HTTP şüpheli payload vb.
      - AI Motoru: CICIDS2017/benzeri veriyle eğitilmiş modelden tahmin (binary veya multi-class destek).
    Not: HTTPS payload içerik analizi mümkün değildir (TLS şifreli). O tarafta davranışsal/akış bazlı tespit yapılır.
    """

    def __init__(self, secilen_arayuz: str, baslangic_sayisi: int = 0):
        self.arayuz = secilen_arayuz
        self.calisiyor = False

        self.db = VeritabaniYoneticisi()

        self.toplam_paket_sayisi = int(baslangic_sayisi or 0)
        self.son_paketler = deque(maxlen=40)

        # Kural motoru state (IP bazlı)
        self._ip_state: Dict[str, Dict[str, Any]] = {}

        # Flow (akış) state (AI için)
        self.akislar: Dict[Tuple, AkisIstatistikcisi] = {}
        self.akis_son_gorulme: Dict[Tuple, float] = {}
        self.flow_timeout_sn = 15

        # Spam koruması
        self._son_log_zamani: Dict[Tuple[str, str], float] = {}

        # Sniffer
        self.sniffer: Optional[AsyncSniffer] = None

        # AI parçaları
        self.model = None
        self.scaler = None
        self.encoder = None
        self.model_modu = "none"  # none | binary | multiclass
        self._ai_yukle()

    # -------------------- AI YÜKLEME --------------------
    def _ai_yukle(self):
        if tf is None:
            print("[AI] TensorFlow yok, AI devre dışı.")
            return

        proje_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

        model_dir_candidates = [
            os.path.join(proje_root, "modeller"),
            os.path.join(proje_root, "model_dosyalar"),
        ]

        model_path = None
        scaler_path = None
        encoder_path = None

        model_candidates = ["trafik_uzman.h5", "lstm_anomali.h5", "lstm_anomali.keras", "trafik_uzman.keras"]
        scaler_candidates = ["uzman_scaler.pkl", "ozellik_olceklendirici.pkl"]
        encoder_candidates = ["uzman_encoder.pkl"]  # varsa multi-class

        for d in model_dir_candidates:
            for m in model_candidates:
                p = os.path.join(d, m)
                if os.path.exists(p):
                    model_path = p
                    break
            for s in scaler_candidates:
                p = os.path.join(d, s)
                if os.path.exists(p):
                    scaler_path = p
                    break
            for e in encoder_candidates:
                p = os.path.join(d, e)
                if os.path.exists(p):
                    encoder_path = p
                    break
            if model_path and scaler_path:
                break

        if not model_path or not scaler_path:
            print("[AI] Model/scaler bulunamadı, AI devre dışı.")
            return

        try:
            print(f"[AI] Model yükleniyor: {model_path}")
            self.model = tf.keras.models.load_model(model_path)
            print(f"[AI] Scaler yükleniyor: {scaler_path}")
            self.scaler = joblib.load(scaler_path)

            if encoder_path and os.path.exists(encoder_path):
                print(f"[AI] Encoder yükleniyor: {encoder_path}")
                self.encoder = joblib.load(encoder_path)
                self.model_modu = "multiclass"
            else:
                self.model_modu = "binary"

        except Exception as e:
            print(f"[AI] Yükleme hatası: {e}")
            self.model = None
            self.scaler = None
            self.encoder = None
            self.model_modu = "none"

    # -------------------- FLOW KİMLİĞİ --------------------
    def akis_kimligi(self, paket) -> Optional[Tuple]:
        if IP not in paket:
            return None

        src = paket[IP].src
        dst = paket[IP].dst
        proto = paket[IP].proto

        sport = 0
        dport = 0
        if TCP in paket:
            sport = paket[TCP].sport
            dport = paket[TCP].dport
        elif UDP in paket:
            sport = paket[UDP].sport
            dport = paket[UDP].dport
        else:
            return None

        a = (src, sport)
        b = (dst, dport)
        key = tuple(sorted([a, b])) + (proto, dport)
        return key

    def _akis_temizle(self, simdi: float):
        if not self.akis_son_gorulme:
            return
        silinecek = []
        for k, last in self.akis_son_gorulme.items():
            if simdi - last > self.flow_timeout_sn:
                silinecek.append(k)
        for k in silinecek:
            self.akis_son_gorulme.pop(k, None)
            self.akislar.pop(k, None)

    # -------------------- KURAL MOTORU --------------------
    def kural_motoru(self, paket) -> List[Tuple[str, float]]:
        """
        Kural bazlı tespitler:
          - SYN Flood / DDoS paterni
          - Port Scan
          - SSH/FTP/Telnet brute-force paterni
          - DNS Tunneling şüphesi
          - Plain HTTP üzerinde şüpheli payload (SQLi/XSS/Traversal/Command) şüphesi
        """
        bulgular: List[Tuple[str, float]] = []

        if IP not in paket:
            return bulgular

        src_ip = paket[IP].src
        now = time.time()

        st = self._ip_state.get(src_ip)
        if not st:
            st = {
                "win_start": now,
                "total": 0,
                "syn": 0,
                "ports": set(),
                "ssh": 0,
                "ftp": 0,
                "telnet": 0,
                "dns_q": 0,
            }
            self._ip_state[src_ip] = st

        # Pencereyi yenile (5 sn)
        if now - st["win_start"] > 5:
            st["win_start"] = now
            st["total"] = 0
            st["syn"] = 0
            st["ports"] = set()
            st["ssh"] = 0
            st["ftp"] = 0
            st["telnet"] = 0
            st["dns_q"] = 0

        st["total"] += 1

        # TCP kuralları
        if TCP in paket:
            dport = paket[TCP].dport
            st["ports"].add(dport)

            flags = str(paket[TCP].flags)
            is_syn = ("S" in flags) and ("A" not in flags)
            if is_syn:
                st["syn"] += 1

            # Brute-force paterni (çok kaba, davranışsal)
            if dport == 22 and is_syn:
                st["ssh"] += 1
            if dport == 21 and is_syn:
                st["ftp"] += 1
            if dport == 23 and is_syn:
                st["telnet"] += 1

            # SYN Flood
            if st["total"] > 140 and st["syn"] > int(st["total"] * 0.92):
                bulgular.append(("DDoS (SYN Flood)", 1.0))

            # Port Scan
            if len(st["ports"]) > 25:
                bulgular.append(("Port Scan", 1.0))

            # Brute-force
            if st["ssh"] > 35:
                bulgular.append(("SSH Bruteforce Şüphesi", 0.95))
            if st["ftp"] > 35:
                bulgular.append(("FTP Bruteforce Şüphesi", 0.95))
            if st["telnet"] > 25:
                bulgular.append(("Telnet Bruteforce Şüphesi", 0.92))

            # Plain HTTP payload inceleme (HTTPS değil)
            if paket[TCP].dport in (80, 8080, 8000) or paket[TCP].sport in (80, 8080, 8000):
                if Raw in paket:
                    try:
                        payload = paket[Raw].load[:2048]  # çok büyütme
                        text = payload.decode("latin-1", errors="ignore").lower()

                        # Şüpheli web paternleri (savunma amaçlı eşleştirme)
                        if "union select" in text or "' or '" in text or "1=1" in text:
                            bulgular.append(("SQL Injection Şüphesi", 0.92))
                        if "<script" in text or "onerror=" in text or "onload=" in text:
                            bulgular.append(("XSS Şüphesi", 0.90))
                        if "../" in text or "..%2f" in text:
                            bulgular.append(("Path Traversal Şüphesi", 0.90))
                        if "cmd=" in text or "powershell" in text or "/bin/sh" in text:
                            bulgular.append(("Command Injection Şüphesi", 0.90))

                        # Büyük POST (exfil şüphesi)
                        if text.startswith("post ") and ("content-length:" in text):
                            m = re.search(r"content-length:\s*(\d+)", text)
                            if m:
                                clen = int(m.group(1))
                                if clen > 200000:
                                    bulgular.append(("Şüpheli Büyük HTTP POST", 0.88))
                    except Exception:
                        pass

        # DNS tunneling (davranışsal)
        if UDP in paket and (paket[UDP].dport == 53 or paket[UDP].sport == 53):
            if DNS in paket and getattr(paket[DNS], "qd", None):
                try:
                    qname = paket[DNS].qd.qname.decode(errors="ignore").strip(".")
                    st["dns_q"] += 1

                    labels = qname.split(".")
                    if len(qname) > 70 or len(labels) > 6 or any(len(x) > 55 for x in labels):
                        bulgular.append(("DNS Tunneling Şüphesi", 0.90))
                except Exception:
                    pass

        return bulgular

    # -------------------- AI ANALİZ --------------------
    def ai_analiz(self, paket) -> Tuple[Optional[str], float]:
        if not self.model or not self.scaler or self.model_modu == "none":
            return None, 0.0
        if IP not in paket:
            return None, 0.0

        kimlik = self.akis_kimligi(paket)
        if not kimlik:
            return None, 0.0

        simdi = time.time()
        self.akis_son_gorulme[kimlik] = simdi

        if kimlik not in self.akislar:
            self.akislar[kimlik] = AkisIstatistikcisi()

        ist = self.akislar[kimlik]

        yon = 1 if paket[IP].src == kimlik[0][0] else -1
        bayrak = paket[TCP].flags if TCP in paket else ""
        ist.paket_ekle(yon, len(paket), str(bayrak), simdi)

        pkt_say = (ist.fwd_pkts + ist.bwd_pkts)

        # Her 15 pakette bir bak
        if pkt_say % 15 != 0:
            return None, 0.0

        try:
            feat = ist.oznitelikleri_al()  # 24 feature
            # Portu ilk feature'a koyma yaklaşımı (modelin böyle eğitildiyse)
            feat[0] = kimlik[2] if len(kimlik) > 2 else 0

            scaled = self.scaler.transform([feat])
            n = scaled.shape[1]
            x = scaled.reshape((1, 1, n))

            preds = self.model.predict(x, verbose=0)

            if self.model_modu == "multiclass":
                idx = int(np.argmax(preds))
                skor = float(np.max(preds))
                etiket = self.encoder.inverse_transform([idx])[0] if self.encoder is not None else "Anomali"
                if str(etiket).lower() != "normal" and skor >= 0.90:
                    return str(etiket), skor
                return None, 0.0

            # binary
            p = preds
            if isinstance(p, (list, tuple)):
                p = np.array(p)

            p = np.array(p).reshape(-1)
            # 2 çıkışlı softmax olabilir
            if p.shape[0] == 2:
                skor = float(p[1])
            else:
                skor = float(p[0])

            if skor >= 0.90:
                return "AI Anomali", skor

        except Exception:
            return None, 0.0

        return None, 0.0

    # -------------------- LOG --------------------
    def logla(self, paket, sonuc: str, skor: float):
        if IP not in paket:
            return

        src = paket[IP].src
        dst = paket[IP].dst
        proto = int(paket[IP].proto)

        sport = 0
        dport = 0
        if TCP in paket:
            sport = int(paket[TCP].sport)
            dport = int(paket[TCP].dport)
        elif UDP in paket:
            sport = int(paket[UDP].sport)
            dport = int(paket[UDP].dport)

        # Spam engeli (aynı src + aynı sonuç 1 sn içinde birden fazla yazmasın)
        k = (src, sonuc)
        now = time.time()
        last = self._son_log_zamani.get(k, 0.0)
        if now - last < 1.0:
            return
        self._son_log_zamani[k] = now

        db_verisi = {
            "src_ip": src,
            "dst_ip": dst,
            "src_port": sport,
            "dst_port": dport,
            "protocol": proto,
        }
        self.db.log_ekle(db_verisi, tahmin_sonucu=sonuc, skor=float(skor))

    # -------------------- PAKET ÖZETİ --------------------
    def _paket_ozeti_ekle(self, paket):
        if IP not in paket:
            return

        proto = "IP"
        port = 0
        dst_ip = paket[IP].dst
        if TCP in paket:
            proto = "TCP"
            port = int(paket[TCP].dport)
        elif UDP in paket:
            proto = "UDP"
            port = int(paket[UDP].dport)

        self.son_paketler.append(
            {
                "src": paket[IP].src,
                "dst": dst_ip,
                "proto": proto,
                "port": port,
                "len": len(paket),
                "time": time.strftime("%H:%M:%S"),
            }
        )

    # -------------------- PAKET İŞLE --------------------
    def paketi_isle(self, paket):
        if not self.calisiyor:
            return
        try:
            self.toplam_paket_sayisi += 1
            self._paket_ozeti_ekle(paket)

            # 1) Kurallar (bariz saldırılar)
            bulgular = self.kural_motoru(paket)
            if bulgular:
                # En yüksek skorlu bulguyu logla
                bulgular.sort(key=lambda x: x[1], reverse=True)
                sonuc, skor = bulgular[0]
                self.logla(paket, sonuc, skor)
                return

            # 2) AI (anomaliler / class)
            etiket, skor = self.ai_analiz(paket)
            if etiket:
                self.logla(paket, etiket, skor)

            # Periodik flow temizliği
            if self.toplam_paket_sayisi % 400 == 0:
                self._akis_temizle(time.time())

        except Exception:
            pass

    # -------------------- START/STOP --------------------
    def baslat(self):
        if self.calisiyor:
            return
        self.calisiyor = True
        self.sniffer = AsyncSniffer(iface=self.arayuz, prn=self.paketi_isle, store=False)
        self.sniffer.start()

    def durdur(self):
        self.calisiyor = False
        try:
            if self.sniffer:
                self.sniffer.stop()
        except Exception:
            pass
