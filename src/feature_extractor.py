import numpy as np
import time

class AkisIstatistikcisi:
    def __init__(self):
        self.baslangic = time.time()
        self.son_gorulme = time.time()
        self.fwd_pkt_lens = []
        self.bwd_pkt_lens = []
        self.fwd_last_time = 0
        self.bwd_last_time = 0
        self.flow_iats = [] 
        self.syn_count = 0; self.ack_count = 0; self.rst_count = 0; self.fin_count = 0
        self.fwd_pkts = 0; self.bwd_pkts = 0

    def paket_ekle(self, paket_yonu, boyut, bayraklar, zaman):
        simdi = zaman
        if self.fwd_last_time == 0 and self.bwd_last_time == 0: self.baslangic = simdi
        
        onceki_zaman = max(self.fwd_last_time, self.bwd_last_time)
        if onceki_zaman > 0: self.flow_iats.append((simdi - onceki_zaman) * 1000000)
            
        self.son_gorulme = simdi

        if paket_yonu == 1: 
            self.fwd_pkts += 1; self.fwd_pkt_lens.append(boyut); self.fwd_last_time = simdi
        else: 
            self.bwd_pkts += 1; self.bwd_pkt_lens.append(boyut); self.bwd_last_time = simdi

        if 'S' in bayraklar: self.syn_count += 1
        if 'A' in bayraklar: self.ack_count += 1
        if 'R' in bayraklar: self.rst_count += 1
        if 'F' in bayraklar: self.fin_count += 1

    def oznitelikleri_al(self):
        sure_sn = self.son_gorulme - self.baslangic
        if sure_sn == 0: sure_sn = 0.000001
        
        all_lens = self.fwd_pkt_lens + self.bwd_pkt_lens
        if not all_lens: all_lens = [0]
        
        pkt_std = np.std(all_lens); pkt_var = np.var(all_lens)
        
        if self.fwd_pkt_lens:
            fwd_mean = np.mean(self.fwd_pkt_lens); fwd_max = np.max(self.fwd_pkt_lens); fwd_min = np.min(self.fwd_pkt_lens); total_fwd_len = np.sum(self.fwd_pkt_lens)
        else: fwd_mean=0; fwd_max=0; fwd_min=0; total_fwd_len=0

        if self.bwd_pkt_lens:
            bwd_mean = np.mean(self.bwd_pkt_lens); bwd_max = np.max(self.bwd_pkt_lens); bwd_min = np.min(self.bwd_pkt_lens); total_bwd_len = np.sum(self.bwd_pkt_lens)
        else: bwd_mean=0; bwd_max=0; bwd_min=0; total_bwd_len=0

        if self.flow_iats:
            iat_mean = np.mean(self.flow_iats); iat_std = np.std(self.flow_iats); iat_max = np.max(self.flow_iats); iat_min = np.min(self.flow_iats)
        else: iat_mean=0; iat_std=0; iat_max=0; iat_min=0

        features = [
            0, sure_sn * 1000000, self.fwd_pkts, self.bwd_pkts, total_fwd_len, total_bwd_len,
            fwd_mean, bwd_mean, pkt_std, pkt_var, fwd_max, fwd_min, bwd_max, bwd_min,
            iat_mean, iat_std, iat_max, iat_min,
            self.syn_count, self.ack_count, self.rst_count, self.fin_count,
            (self.fwd_pkts + self.bwd_pkts) / sure_sn, (total_fwd_len + total_bwd_len) / sure_sn
        ]
        return np.array(features)
