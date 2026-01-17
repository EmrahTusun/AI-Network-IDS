from flask import Flask, render_template, jsonify, request
import os
import sys
import psutil

from src.ids_motoru import IDSMotoru
from src.moduller.veritabani_yoneticisi import VeritabaniYoneticisi

app = Flask(__name__, template_folder="web_arayuz/templates", static_folder="web_arayuz/static")

motor_instance = None
sistem_durumu = "Pasif"

SAYAC_DOSYASI = "veriler/sayac.txt"


def sayac_yukle() -> int:
    try:
        if os.path.exists(SAYAC_DOSYASI):
            with open(SAYAC_DOSYASI, "r") as f:
                return int(f.read().strip() or "0")
    except Exception:
        pass
    return 0


def sayac_kaydet(deger: int):
    os.makedirs("veriler", exist_ok=True)
    with open(SAYAC_DOSYASI, "w") as f:
        f.write(str(int(deger)))


@app.route("/")
def index():
    interfaces = list(psutil.net_if_addrs().keys())
    return render_template("index.html", interfaces=interfaces)


@app.route("/api/baslat", methods=["POST"])
def sistemi_baslat():
    global motor_instance, sistem_durumu

    if sistem_durumu == "Aktif":
        return jsonify({"status": "error", "message": "Sistem zaten aktif."})

    data = request.get_json(silent=True) or {}
    iface = data.get("interface")

    interfaces = list(psutil.net_if_addrs().keys())
    if iface not in interfaces:
        return jsonify({"status": "error", "message": f"Geçersiz arayüz: {iface}"}), 400

    try:
        motor_instance = IDSMotoru(iface, baslangic_sayisi=sayac_yukle())
        motor_instance.baslat()
        sistem_durumu = "Aktif"
        return jsonify({"status": "success"})
    except Exception as e:
        sistem_durumu = "Pasif"
        motor_instance = None
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/durdur", methods=["POST"])
def sistemi_durdur():
    global motor_instance, sistem_durumu

    if motor_instance and sistem_durumu == "Aktif":
        motor_instance.durdur()
        sistem_durumu = "Pasif"
        sayac_kaydet(motor_instance.toplam_paket_sayisi)
        return jsonify({"status": "success"})

    return jsonify({"status": "error", "message": "Sistem aktif değil."})


@app.route("/api/temizle", methods=["POST"])
def loglari_temizle():
    global motor_instance

    db = VeritabaniYoneticisi()
    db.tum_loglari_temizle(reset_identity=True)
    db.kapat()

    sayac_kaydet(0)

    # RAM state reset
    if motor_instance:
        motor_instance.toplam_paket_sayisi = 0
        motor_instance.son_paketler.clear()
        motor_instance.akislar.clear()
        motor_instance.akis_son_gorulme.clear()
        motor_instance._ip_state.clear()

    return jsonify({"status": "success"})


@app.route("/api/veriler")
def get_veriler():
    global motor_instance, sistem_durumu

    db = VeritabaniYoneticisi()

    # Loglar (son 20)
    rows = db.son_loglari_getir(limit=20)
    loglar = []
    for r in rows:
        tarih = (r["tarih"] or "")
        saat = tarih.split(" ")[1] if " " in tarih else tarih
        loglar.append(
            {
                "tarih": saat,
                "src_ip": r["src_ip"],
                "dst_ip": r["dst_ip"],
                "tahmin_sonucu": r["tahmin_sonucu"],
                "tahmin_skoru": r["tahmin_skoru"],
            }
        )

    # Özet
    ozet = db.saldiri_ozeti_getir()

    # Saldırganlar (ip + sayi + tur)
    saldirganlar = db.saldirgan_istatistik_getir(limit=10)

    db.kapat()

    # Paket sayacı + canlı trafik
    pkt = sayac_yukle()
    son = []
    if motor_instance:
        pkt = motor_instance.toplam_paket_sayisi
        son = list(motor_instance.son_paketler)
        son.reverse()

        if sistem_durumu == "Aktif" and pkt % 80 == 0:
            sayac_kaydet(pkt)

    return jsonify(
        {
            "saldirilar": loglar,
            "saldirganlar": saldirganlar,
            "ozet": ozet,
            "toplam_saldiri": ozet.get("toplam_saldiri", 0),
            "toplam_paket": pkt,
            "son_paketler": son,
            "sistem_durumu": sistem_durumu,
        }
    )


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[HATA] Ağ dinleme için root gerekli. Şöyle çalıştır: sudo -E python3 main.py")
        sys.exit(1)

    os.makedirs("veriler", exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=False)
