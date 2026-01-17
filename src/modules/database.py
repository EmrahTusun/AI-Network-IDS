import sqlite3
import os
from typing import Any, Dict, List, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_DOSYASI = os.path.join(BASE_DIR, "veriler", "guvenlik_loglari.db")


class VeritabaniYoneticisi:
    def __init__(self):
        self.conn = None
        self.cursor = None
        self.baglanti_kur()

    def baglanti_kur(self):
        os.makedirs(os.path.dirname(DB_DOSYASI), exist_ok=True)
        self.conn = sqlite3.connect(DB_DOSYASI, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self.tablo_olustur()
        self._migrate_if_needed()

    def tablo_olustur(self):
        sql = """
        CREATE TABLE IF NOT EXISTS trafik_loglari (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tarih TEXT DEFAULT (datetime('now','localtime')),
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol INTEGER,
            tahmin_sonucu TEXT,
            tahmin_skoru REAL
        )
        """
        self.cursor.execute(sql)
        self.conn.commit()

    def _migrate_if_needed(self):
        """
        Eski DB varsa bozmadan küçük eklemeler yapabilmek için yer bırakıyoruz.
        Şimdilik tablo yapısı aynı. (Gelecekte sütun eklemek istersen burası hazır.)
        """
        # Örnek:
        # cols = [r["name"] for r in self.cursor.execute("PRAGMA table_info(trafik_loglari)").fetchall()]
        # if "tespit_kaynagi" not in cols:
        #     self.cursor.execute("ALTER TABLE trafik_loglari ADD COLUMN tespit_kaynagi TEXT")
        #     self.conn.commit()
        return

    def log_ekle(self, veri: Dict[str, Any], tahmin_sonucu: str, skor: float) -> bool:
        try:
            sql = """
            INSERT INTO trafik_loglari
            (src_ip, dst_ip, src_port, dst_port, protocol, tahmin_sonucu, tahmin_skoru)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """
            self.cursor.execute(
                sql,
                (
                    str(veri.get("src_ip", "")),
                    str(veri.get("dst_ip", "")),
                    int(veri.get("src_port", 0) or 0),
                    int(veri.get("dst_port", 0) or 0),
                    int(veri.get("protocol", 0) or 0),
                    str(tahmin_sonucu),
                    float(skor),
                ),
            )
            self.conn.commit()
            return True
        except Exception as e:
            print(f"[DB HATASI] {e}")
            return False

    def tum_loglari_temizle(self, reset_identity: bool = True) -> None:
        self.cursor.execute("DELETE FROM trafik_loglari")
        if reset_identity:
            try:
                self.cursor.execute("DELETE FROM sqlite_sequence WHERE name='trafik_loglari'")
            except Exception:
                pass
        self.conn.commit()
        try:
            self.cursor.execute("VACUUM")
            self.conn.commit()
        except Exception:
            pass

    def saldiri_ozeti_getir(self) -> Dict[str, Any]:
        ozet = {"toplam_saldiri": 0, "en_tehlikeli_ip": "Yok", "en_yaygin_saldiri": "Yok"}
        try:
            self.cursor.execute("SELECT COUNT(*) AS c FROM trafik_loglari")
            ozet["toplam_saldiri"] = int(self.cursor.fetchone()["c"])

            self.cursor.execute("""
                SELECT src_ip, COUNT(*) AS sayi
                FROM trafik_loglari
                GROUP BY src_ip
                ORDER BY sayi DESC
                LIMIT 1
            """)
            ip = self.cursor.fetchone()
            if ip:
                ozet["en_tehlikeli_ip"] = ip["src_ip"]

            self.cursor.execute("""
                SELECT tahmin_sonucu, COUNT(*) AS sayi
                FROM trafik_loglari
                GROUP BY tahmin_sonucu
                ORDER BY sayi DESC
                LIMIT 1
            """)
            tur = self.cursor.fetchone()
            if tur:
                ozet["en_yaygin_saldiri"] = tur["tahmin_sonucu"]
        except Exception:
            pass
        return ozet

    def son_loglari_getir(self, limit: int = 20) -> List[sqlite3.Row]:
        try:
            self.cursor.execute("SELECT * FROM trafik_loglari ORDER BY id DESC LIMIT ?", (int(limit),))
            return self.cursor.fetchall()
        except Exception:
            return []

    def saldirgan_istatistik_getir(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        IP + saldırı sayısı + max skor + o IP'nin en baskın saldırı türü
        """
        try:
            self.cursor.execute(
                """
                SELECT
                    t1.src_ip AS ip,
                    COUNT(*) AS sayi,
                    MAX(t1.tahmin_skoru) AS max_skor,
                    (
                        SELECT tahmin_sonucu
                        FROM trafik_loglari t2
                        WHERE t2.src_ip = t1.src_ip
                        GROUP BY tahmin_sonucu
                        ORDER BY COUNT(*) DESC
                        LIMIT 1
                    ) AS tur
                FROM trafik_loglari t1
                GROUP BY t1.src_ip
                ORDER BY sayi DESC
                LIMIT ?
                """,
                (int(limit),),
            )
            rows = self.cursor.fetchall()
            out = []
            for r in rows:
                out.append(
                    {
                        "ip": r["ip"],
                        "sayi": int(r["sayi"]),
                        "max_skor": float(r["max_skor"] or 0.0),
                        "tur": r["tur"] or "—",
                    }
                )
            return out
        except Exception:
            return []

    def kapat(self):
        try:
            if self.conn:
                self.conn.close()
        except Exception:
            pass
