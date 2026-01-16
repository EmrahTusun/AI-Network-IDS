import os

# Proje kök dizini
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Veritabanı ayarları
DB_PATH = os.path.join(BASE_DIR, "data", "security_logs.db")

# Model ayarları
MODEL_DIR = os.path.join(BASE_DIR, "models")
MODEL_PATH = os.path.join(MODEL_DIR, "trafik_uzman.h5")
SCALER_PATH = os.path.join(MODEL_DIR, "uzman_scaler.pkl")
ENCODER_PATH = os.path.join(MODEL_DIR, "uzman_encoder.pkl")

# IDS ayarları
FLOW_TIMEOUT = 15  # saniye
AI_ANALYSIS_INTERVAL = 15  # her X pakette bir
DETECTION_THRESHOLD = 0.90

# Web ayarları
WEB_HOST = "0.0.0.0"
WEB_PORT = 5000
DEBUG = False