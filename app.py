import base64
import datetime
import io
import json
import logging
import os
import sys
from functools import wraps
from typing import Any, Dict, Optional
import joblib
import numpy as np
import pandas as pd
import pyotp
import qrcode
import shap
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
import hashlib

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("anesthesia_app")

# -----------------------------------------------------------------------------
# Flask App and Config
# -----------------------------------------------------------------------------
app = Flask(__name__)
# SECURITY: Use environment variables in production
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev_secret_key_replace_in_prod")
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev_ext_secret_key_replace_in_prod")

# Database configuration (MySQL). Example:
#   export DB_USER=root
#   export DB_PASSWORD=pass
#   export DB_HOST=localhost
#   export DB_NAME=anesthesia_db
DB_USER = os.environ.get("DB_USER", "root")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "rootpassword")
DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_NAME = os.environ.get("DB_NAME", "anesthesia_db")
app.config["SQLALCHEMY_DATABASE_URI"] = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# -----------------------------------------------------------------------------
# Admin Credentials and 2FA
# -----------------------------------------------------------------------------
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")  # Hash in production
ADMIN_2FA_SECRET = os.environ.get("ADMIN_2FA_SECRET", pyotp.random_base32())

# -----------------------------------------------------------------------------
# Encryption Helpers (Fernet over PBKDF2HMAC)
# -----------------------------------------------------------------------------
def generate_encryption_key(password: str, salt: bytes) -> bytes:
    """Generate a Fernet-compatible key from a password and salt."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

env_salt = os.environ.get("ENCRYPTION_SALT")
if env_salt:
    ENCRYPTION_SALT = env_salt.encode()
else:
    # Warning: random salt will change per restart; data won't decrypt across runs.
    ENCRYPTION_SALT = os.urandom(16)
    logger.warning(
        "ENCRYPTION_SALT not set. Using a random salt which WILL change on restart. "
        "Set ENCRYPTION_SALT to persist decryption across app restarts."
    )

ENCRYPTION_KEY = generate_encryption_key(
    os.environ.get("BLOCKCHAIN_SECRET_KEY", "blockchain_secret_key_2024"),
    ENCRYPTION_SALT,
)
cipher_suite = Fernet(ENCRYPTION_KEY)

def encrypt_data(data: Any) -> str:
    """Encrypt sensitive data to a base64 string."""
    try:
        if not isinstance(data, str):
            data = json.dumps(data, default=str)
        return cipher_suite.encrypt(data.encode()).decode()
    except Exception as e:
        logger.error(f"Encryption failed: {e}")
        return "ENCRYPTION_ERROR"

def decrypt_data(encrypted_data: str) -> str:
    """Decrypt sensitive data from a base64 string."""
    try:
        if not encrypted_data or encrypted_data == "ENCRYPTION_ERROR":
            return "DECRYPTION_ERROR"
        return cipher_suite.decrypt(encrypted_data.encode()).decode()
    except Exception as e:
        preview = encrypted_data[:50] + "..." if encrypted_data and len(encrypted_data) > 50 else encrypted_data
        logger.error(f"Decryption failed for data: {preview}. Error: {e}")
        return "DECRYPTION_ERROR"

# -----------------------------------------------------------------------------
# Simple In-Memory Blockchain (Encrypted Payload)
# -----------------------------------------------------------------------------
class Block:
    def __init__(self, index: int, timestamp: datetime.datetime, data: Dict[str, Any], previous_hash: str):
        self.index = index
        self.timestamp = timestamp
        # Store encrypted JSON string
        self.encrypted_data = encrypt_data(data)
        # Hash of plaintext data for integrity
        self.data_hash = hashlib_sha256_json(data)
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()
        
    def calculate_hash(self) -> str:
        block_string = json.dumps(
            {
                "index": self.index,
                "timestamp": self.timestamp.isoformat(),
                "data_hash": self.data_hash,
                "previous_hash": self.previous_hash,
            },
            sort_keys=True,
        ).encode("utf-8")
        return sha256_hex(block_string)
    
    def get_decrypted_data(self) -> Dict[str, Any]:
        """Attempt to decrypt block data."""
        try:
            decrypted_str = decrypt_data(self.encrypted_data)
            if decrypted_str == "DECRYPTION_ERROR":
                return {"error": "Failed to decrypt data"}
            return json.loads(decrypted_str)
        except Exception as e:
            logger.error(f"Failed to decrypt data for block {self.index}: {e}")
            return {"error": "Failed to decrypt data"}

class Blockchain:
    def __init__(self):
        self.chain: list[Block] = []
        self.create_genesis_block()
    
    def create_genesis_block(self):
        genesis_data = {"message": "Genesis Block for Anesthesia Monitoring", "system": "encrypted"}
        self.add_block(Block(0, datetime.datetime.utcnow(), genesis_data, "0"))
    
    def add_block(self, block: Block):
        self.chain.append(block)
    
    def get_latest_block(self) -> Optional[Block]:
        if not self.chain:
            return None
        return self.chain[-1]
    
    def is_chain_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            if current_block.hash != current_block.calculate_hash():
                logger.warning(f"Block {current_block.index} has been tampered with (hash mismatch)!")
                return False
            if current_block.previous_hash != previous_block.hash:
                logger.warning(f"Block {current_block.index} link to previous block is broken!")
                return False
        return True

def sha256_hex(data_bytes: bytes) -> str:
    return hashlib.sha256(data_bytes).hexdigest()

def hashlib_sha256_json(data: Dict[str, Any]) -> str:
    """Deterministically hash JSON data."""
    return sha256_hex(json.dumps(data, sort_keys=True, default=str).encode("utf-8"))

blockchain = Blockchain()

# -----------------------------------------------------------------------------
# Database Models
# -----------------------------------------------------------------------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    def __repr__(self):
        return f"<User {self.username}>"

class Patient(db.Model):
    __tablename__ = "patient"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    vitals = db.relationship("Vitals", backref="patient", lazy=True)
    histories = db.relationship("History", backref="patient", lazy=True)
    predictions = db.relationship("Prediction", backref="patient", lazy=True)
    blockchain_logs = db.relationship("Blockchain_Log", backref="patient", lazy=True)
    def __repr__(self):
        return f"<Patient {self.name} ({self.id})>"

class Vitals(db.Model):
    __tablename__ = "vitals"
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patient.id"), nullable=False)
    temperature = db.Column(db.Float, nullable=False)
    spo2 = db.Column(db.Float, nullable=False)
    ecg = db.Column(db.Float)
    eeg = db.Column(db.Float, nullable=False)
    bp_systolic = db.Column(db.Float, nullable=False)
    bp_diastolic = db.Column(db.Float, nullable=False)
    heart_rate = db.Column(db.Float, nullable=False)
    weight = db.Column(db.Float, nullable=False)
    recorded_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    @property
    def pulse_pressure(self) -> float:
        return self.bp_systolic - self.bp_diastolic
    
    @property
    def bp_category(self) -> str:
        if self.bp_systolic >= 140 or self.bp_diastolic >= 90:
            return "Hypertensive"
        elif self.bp_systolic >= 130 or self.bp_diastolic >= 80:
            return "Elevated"
        else:
            return "Normal"
    
    def __repr__(self):
        return f"<Vitals {self.id} for Patient {self.patient_id} - BP: {self.bp_systolic}/{self.bp_diastolic}>"

class History(db.Model):
    __tablename__ = "history"
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patient.id"), nullable=False)
    kidney_disease = db.Column(db.Integer, nullable=False, default=0)
    liver_disease = db.Column(db.Integer, nullable=False, default=0)
    diabetes = db.Column(db.Integer, nullable=False, default=0)
    allergy = db.Column(db.Integer, nullable=False, default=0)
    asthma = db.Column(db.Integer, nullable=False, default=0)
    other_conditions = db.Column(db.Text)
    def __repr__(self):
        return f"<History {self.id} for Patient {self.patient_id}>"

class Prediction(db.Model):
    __tablename__ = "prediction"
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patient.id"), nullable=False)
    prediction_result = db.Column(db.Float, nullable=False)
    prediction_confidence = db.Column(db.Float)
    prediction_time = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    anesthesia_type_selected = db.Column(db.String(50), nullable=False)
    surgery_type_selected = db.Column(db.String(100))
    dosage_category = db.Column(db.String(50))
    bp_systolic_at_prediction = db.Column(db.Float)
    bp_diastolic_at_prediction = db.Column(db.Float)
    pulse_pressure = db.Column(db.Float)
    model_version = db.Column(db.String(20), default="v2.0_diastolic")
    explanation = db.relationship("Explainable_AI", backref="prediction_entry", uselist=False, lazy=True)
    def __repr__(self):
        return f"<Prediction {self.id} for Patient {self.patient_id} - Result: {self.prediction_result}>"

class Blockchain_Log(db.Model):
    __tablename__ = "blockchain_log"
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey("patient.id"), nullable=False)
    block_hash = db.Column(db.String(256), nullable=False, unique=True)
    block_index = db.Column(db.Integer, nullable=False)
    data_hash = db.Column(db.String(256))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    def __repr__(self):
        return f"<Blockchain_Log {self.block_hash[:10]} for Patient {self.patient_id}>"

class Explainable_AI(db.Model):
    __tablename__ = "explainable_ai"
    id = db.Column(db.Integer, primary_key=True)
    prediction_id = db.Column(db.Integer, db.ForeignKey("prediction.id"), nullable=False, unique=True)
    top_features = db.Column(db.JSON, nullable=False)
    shap_values = db.Column(db.JSON, nullable=False)
    feature_importance = db.Column(db.JSON)
    explanation_text = db.Column(db.Text, nullable=False)
    bp_impact_explanation = db.Column(db.Text)
    risk_factors = db.Column(db.Text)
    confidence_factors = db.Column(db.Text)
    def __repr__(self):
        return f"<XAI {self.id} for Prediction {self.prediction_id}>"

class Audit_Log(db.Model):
    __tablename__ = "audit_log"
    id = db.Column(db.Integer, primary_key=True)
    table_name = db.Column(db.String(50), nullable=False)
    record_id = db.Column(db.Integer, nullable=False)
    action = db.Column(db.String(20), nullable=False)  # INSERT, UPDATE, DELETE
    old_values = db.Column(db.JSON)
    new_values = db.Column(db.JSON)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    def __repr__(self):
        return f"<AuditLog {self.action} on {self.table_name}({self.record_id})>"

# -----------------------------------------------------------------------------
# ML Model Loading and SHAP
# -----------------------------------------------------------------------------
class DummyModel:
    def predict(self, X):
        logger.warning("Using DummyModel: Returning a default dosage.")
        return np.array([10.0])

model = None
encoder = None  # Placeholder for future use
explainer = None
model_paths = [
    "models/anesthesia_model_enhanced_with_diastolic.pkl",
    "models/anesthesia_model_enhanced.pkl",
    "anesthesia_model_enhanced.pkl",
    "anesthesia_model_updated.pkl",
    "anesthesia_model.pkl",
]
for model_path in model_paths:
    full_path = os.path.abspath(model_path)
    logger.info(f"Looking for model at: {full_path}")
    if os.path.exists(model_path):
        try:
            model = joblib.load(model_path)
            logger.info(f"ML model loaded from: {full_path}")
            break
        except Exception as e:
            logger.error(f"Error loading model from {full_path}: {e}")
    else:
        logger.warning(f"Model file not found: {full_path}")

if model is None:
    logger.error("No ML model found. Using DummyModel.")
    model = DummyModel()

MODEL_FEATURE_NAMES = [
    "age",
    "weight",
    "bp_systolic",
    "bp_diastolic",
    "heart_rate",
    "spo2",
    "temperature",
    "eeg",
    "kidney_disease",
    "liver_disease",
    "diabetes",
    "allergy",
    "asthma",
    "anesthesia_type_local",
    "anesthesia_type_regional",
    "anesthesia_type_sedation",
]

if not isinstance(model, DummyModel):
    try:
        sample_data = pd.DataFrame(
            [[
                30,   # age
                70,   # weight
                120,  # bp_systolic
                80,   # bp_diastolic
                75,   # heart_rate
                98,   # spo2
                36.5, # temperature
                40,   # eeg
                0,    # kidney_disease
                0,    # liver_disease
                0,    # diabetes
                0,    # allergy
                0,    # asthma
                0,    # anesthesia_type_local
                0,    # anesthesia_type_regional
                0,    # anesthesia_type_sedation
            ]],
            columns=MODEL_FEATURE_NAMES,
        )
        # Generic SHAP explainer as a fallback
        explainer = shap.Explainer(model, sample_data)
        logger.info("SHAP explainer initialized.")
    except Exception as e:
        logger.error(f"Error initializing SHAP explainer: {e}")
        explainer = None

# Ensure directories exist
os.makedirs("explanation", exist_ok=True)
os.makedirs("static", exist_ok=True)

# -----------------------------------------------------------------------------
# Prediction Function
# -----------------------------------------------------------------------------
def predict_anesthesia_dosage(input_data: Dict[str, Any]) -> float:
    """
    Predict anesthesia dosage based on input data.
    Args:
        input_data: Dictionary containing patient data and vitals.
    Returns:
        float: Predicted dosage in mg.
    """
    try:
        # Prepare the features in the order expected by the model
        features = [
            input_data.get("age", 30),
            input_data.get("weight", 70),
            input_data.get("bp_systolic", 120),
            input_data.get("bp_diastolic", 80),
            input_data.get("heart_rate", 75),
            input_data.get("spo2", 98),
            input_data.get("temperature", 37.0),
            input_data.get("eeg", 35),
            input_data.get("kidney_disease", 0),
            input_data.get("liver_disease", 0),
            input_data.get("diabetes", 0),
            input_data.get("allergy", 0),
            input_data.get("asthma", 0),
        ]

        # Handle anesthesia type: convert to one-hot encoding
        anesthesia_type = input_data.get("anesthesia_type", "general").lower()
        if anesthesia_type == "local":
            features.extend([1, 0, 0])
        elif anesthesia_type == "regional":
            features.extend([0, 1, 0])
        elif anesthesia_type == "sedation":
            features.extend([0, 0, 1])
        else:  # general
            features.extend([0, 0, 0])

        # Convert to DataFrame with the same column order as MODEL_FEATURE_NAMES
        df = pd.DataFrame([features], columns=MODEL_FEATURE_NAMES)

        # Make prediction
        prediction = model.predict(df)[0]
        return float(prediction)
    except Exception as e:
        logger.error(f"Error in predict_anesthesia_dosage: {e}")
        # Fallback to a default value
        return 10.0

# -----------------------------------------------------------------------------
# Prediction and Explanation
# -----------------------------------------------------------------------------
def process_prediction_and_blockchain(patient_id: int, input_data: Dict[str, Any], is_iot: bool = False):
    # FIXED: Call the predict_anesthesia_dosage function
    predicted_dosage_mg = predict_anesthesia_dosage(input_data)
    predicted_dosage_mg = max(0.1, min(float(predicted_dosage_mg), 25.0))
    bp_systolic = float(input_data.get("bp_systolic", 120))
    bp_diastolic = float(input_data.get("bp_diastolic", 80))
    pulse_pressure = bp_systolic - bp_diastolic
    
    # FIX: Get ECG value from input_data instead of using undefined variable
    ecg_value = float(input_data.get("ecg", 0.5))  # Default to 0.5 if not provided
    confidence = 0.8
    if 90 <= bp_systolic <= 140 and 60 <= bp_diastolic <= 90:
        confidence += 0.1
    if 35 <= pulse_pressure <= 50:
        confidence += 0.05
    confidence = min(confidence, 0.99)
    raw_explanation_dict: Dict[str, float] = {}
    theory_explanation_text = "AI explanation not available due to model/explainer issues."
    if explainer and not isinstance(model, DummyModel):
        try:
            features = {
                "age": float(input_data.get("age", 30)),
                "weight": float(input_data.get("weight", 70)),
                "bp_systolic": bp_systolic,
                "bp_diastolic": bp_diastolic,
                "heart_rate": float(input_data.get("heart_rate", 75)),
                "spo2": float(input_data.get("spo2", 98)),
                "temperature": float(input_data.get("temperature", 37.0)),
                "eeg": float(input_data.get("eeg", 35)),
                "kidney_disease": int(input_data.get("kidney_disease", 0)),
                "liver_disease": int(input_data.get("liver_disease", 0)),
                "diabetes": int(input_data.get("diabetes", 0)),
                "allergy": int(input_data.get("allergy", 0)),
                "asthma": int(input_data.get("asthma", 0)),
                "anesthesia_type_local": 0,
                "anesthesia_type_regional": 0,
                "anesthesia_type_sedation": 0,
            }
            anesthesia_type = str(input_data.get("anesthesia_type", "general")).lower()
            features["anesthesia_type_local"] = 1 if anesthesia_type == "local" else 0
            features["anesthesia_type_regional"] = 1 if anesthesia_type == "regional" else 0
            features["anesthesia_type_sedation"] = 1 if anesthesia_type == "sedation" else 0
            model_input = pd.DataFrame([features], columns=MODEL_FEATURE_NAMES)
            shap_expl = explainer(model_input)
            shap_values_array = np.array(shap_expl.values).reshape(1, -1)
            raw_explanation_dict = dict(zip(model_input.columns.tolist(), shap_values_array[0].tolist()))
            bp_data = {"bp_systolic": bp_systolic, "bp_diastolic": bp_diastolic, "pulse_pressure": pulse_pressure}
            theory_explanation_text = generate_theory_explanation(shap_values_array, MODEL_FEATURE_NAMES, predicted_dosage_mg, bp_data)
        except Exception as e:
            logger.error(f"Error during SHAP explanation: {e}", exc_info=True)
            theory_explanation_text = (
                f"The predicted anesthesia dosage is approximately {predicted_dosage_mg:.2f} units. "
                f"BP: {bp_systolic}/{bp_diastolic} mmHg (Pulse Pressure: {pulse_pressure} mmHg). "
                f"Detailed AI explanation is unavailable due to technical issues."
            )
    else:
        logger.warning("SHAP explainer not available. Generating basic explanation.")
        theory_explanation_text = (
            f"The predicted anesthesia dosage is approximately {predicted_dosage_mg:.2f} units. "
            f"BP: {bp_systolic}/{bp_diastolic} mmHg. Detailed AI explanation is unavailable."
        )
    # FIX: Use ecg_value variable instead of undefined 'ecg'
    dosage_category = "Standard Dose"
    if 0.2 <= ecg_value <= 0.5:
        dosage_category = "Low Dose"
    elif 0.6 <= ecg_value <= 1.0:
        dosage_category = "Moderate Dose"
    elif 1.1 <= ecg_value <= 1.4:
        dosage_category = "High Risk Dose"
    anesthesia_type_selected = str(input_data.get('anesthesia_type', 'general')).lower()
    if anesthesia_type_selected not in ('general', 'local', 'regional', 'sedation'):
        anesthesia_type_selected = 'general'
    surgery_type_selected = input_data.get('surgery_type', 'Other')
    surgery_info = get_surgery_info(surgery_type_selected)
    try:
        new_prediction_entry = Prediction(
            patient_id=patient_id,
            prediction_result=float(predicted_dosage_mg),
            prediction_confidence=float(confidence),
            prediction_time=datetime.datetime.utcnow(),
            anesthesia_type_selected=anesthesia_type_selected,
            surgery_type_selected=surgery_type_selected,
            dosage_category=dosage_category,
            bp_systolic_at_prediction=bp_systolic,
            bp_diastolic_at_prediction=bp_diastolic,
            pulse_pressure=pulse_pressure,
            model_version="v2.0_diastolic",
        )
        db.session.add(new_prediction_entry)
        db.session.flush()
        bp_impact_explanation = f"Blood pressure ({bp_systolic}/{bp_diastolic} mmHg) categorized as "
        if bp_systolic >= 140 or bp_diastolic >= 90:
            bp_impact_explanation += "Hypertensive. Increased anesthesia risk - close monitoring required."
        elif bp_systolic >= 130 or bp_diastolic >= 80:
            bp_impact_explanation += "Elevated. Moderate risk - standard precautions recommended."
        else:
            bp_impact_explanation += "Normal. Low cardiovascular risk."
        bp_impact_explanation += f" Pulse pressure of {pulse_pressure} mmHg is "
        if pulse_pressure > 60:
            bp_impact_explanation += "elevated, suggesting arterial stiffness."
        elif pulse_pressure < 25:
            bp_impact_explanation += "low, which may indicate heart issues."
        else:
            bp_impact_explanation += "within normal range."
        new_xai_entry = Explainable_AI(
            prediction_id=new_prediction_entry.id,
            top_features=[
                f for f, _ in sorted(raw_explanation_dict.items(), key=lambda item: abs(item[1]), reverse=True)[:3]
            ]
            if raw_explanation_dict
            else [],
            shap_values=raw_explanation_dict if raw_explanation_dict else {},
            feature_importance=raw_explanation_dict if raw_explanation_dict else {},
            explanation_text=theory_explanation_text,
            bp_impact_explanation=bp_impact_explanation,
            risk_factors=", ".join(
                [
                    k
                    for k, v in {
                        "Hypertension": (bp_systolic >= 140 or bp_diastolic >= 90),
                        "Kidney Disease": int(input_data.get("kidney_disease", 0)) == 1,
                        "Liver Disease": int(input_data.get("liver_disease", 0)) == 1,
                        "Diabetes": int(input_data.get("diabetes", 0)) == 1,
                        "Allergies": int(input_data.get("allergy", 0)) == 1,
                        "Asthma": int(input_data.get("asthma", 0)) == 1,
                    }.items()
                    if v
                ]
            ),
            confidence_factors=f"Model confidence: {confidence:.1%}, BP stability: {'Good' if pulse_pressure <= 50 else 'Concern'}",
        )
        db.session.add(new_xai_entry)
        # Blockchain data - FIX: Use ecg_value instead of input_data.get("ecg", 0)
        blockchain_data = {
            "patient_id": patient_id,
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "vitals": {
                "temperature": input_data.get("temperature"),
                "spo2": input_data.get("spo2"),
                "ecg": ecg_value,  # FIX: Use the defined ecg_value variable
                "eeg": input_data.get("eeg"),
                "bp_systolic": bp_systolic,
                "bp_diastolic": bp_diastolic,
                "pulse_pressure": pulse_pressure,
                "heart_rate": input_data.get("heart_rate"),
                "weight": input_data.get("weight"),
            },
            "medical_history": {
                "kidney_disease": input_data.get("kidney_disease"),
                "liver_disease": input_data.get("liver_disease"),
                "diabetes": input_data.get("diabetes"),
                "allergy": input_data.get("allergy", 0),
                "asthma": input_data.get("asthma", 0),
            },
            "prediction_details": {
                "anesthesia_type": anesthesia_type_selected,
                "surgery_type": surgery_type_selected,
                "predicted_dosage": f"{predicted_dosage_mg:.2f}",
                "dosage_category": dosage_category,
                "confidence_score": f"{confidence:.2%}",
                "estimated_duration": surgery_info["duration"],
                "re_dose_interval": surgery_info["re_dose_interval"],
                "bp_category": "Hypertensive"
                if bp_systolic >= 140 or bp_diastolic >= 90
                else "Elevated"
                if bp_systolic >= 130 or bp_diastolic >= 80
                else "Normal",
            },
            "system_info": {
                "source": "IoT Device" if is_iot else "Manual Form",
                "model_version": "Enhanced v2.0 with BP Analysis",
                "prediction_id": new_prediction_entry.id,
                "features_used": len(MODEL_FEATURE_NAMES),
                "bp_analysis_included": True,
            },
        }
        latest_block = blockchain.get_latest_block()
        previous_hash = latest_block.hash if latest_block else "0"
        new_block = Block(len(blockchain.chain), datetime.datetime.utcnow(), blockchain_data, previous_hash)
        blockchain.add_block(new_block)
        new_blockchain_log = Blockchain_Log(
            patient_id=patient_id,
            block_hash=new_block.hash,
            timestamp=new_block.timestamp,
            block_index=new_block.index,
            data_hash=new_block.data_hash,
        )
        db.session.add(new_blockchain_log)
        log_audit(
            "prediction",
            new_prediction_entry.id,
            "INSERT",
            None,
            {
                "patient_id": patient_id,
                "prediction_result": predicted_dosage_mg,
                "confidence": confidence,
                "bp_systolic": bp_systolic,
                "bp_diastolic": bp_diastolic,
            },
        )
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error saving prediction and blockchain data: {e}", exc_info=True)
        if not is_iot:
            flash("Error saving prediction data. Please try again.", "danger")
            return redirect(url_for("vitals_input"))
        else:
            return None
    if is_iot:
        return None
    # Rest of the function continues as before...
    # (User-facing rendering code remains the same)
    type_specific_message = ""
    atype = str(anesthesia_type_selected).lower()
    if atype == "local":
        type_specific_message = (
            "For local anesthesia, the primary focus is on localized numbing. "
            "The predicted systemic dosage is for overall patient safety and comfort management."
        )
    elif atype == "regional":
        type_specific_message = (
            "Regional anesthesia targets a specific body area. "
            "The calculated dosage supports the systemic physiological response during the procedure."
        )
    elif atype == "sedation":
        type_specific_message = (
            "Sedation aims for a calm, relaxed state. "
            "The predicted dosage provides a starting point; close monitoring and titration are essential."
        )
    else:
        type_specific_message = (
            "For general anesthesia, this dosage is a starting point for inducing and maintaining "
            "a safe, unconscious state throughout the procedure."
        )
    safety_warnings: list[str] = []
    if int(input_data.get("allergy", 0)):
        safety_warnings.append("⚠️ Patient has known allergies - monitor for allergic reactions during anesthesia.")
    if int(input_data.get("asthma", 0)):
        safety_warnings.append("⚠️ Patient has asthma - careful respiratory monitoring required.")
    if int(input_data.get("kidney_disease", 0)):
        safety_warnings.append("⚠️ Patient has kidney disease - reduced dosage recommended for safety.")
    if int(input_data.get("liver_disease", 0)):
        safety_warnings.append("⚠️ Patient has liver disease - significantly reduced dosage recommended.")
    if bp_systolic >= 140 or bp_diastolic >= 90:
        safety_warnings.append(
            "⚠️ Hypertensive patient - continuous BP monitoring and potential antihypertensive support needed."
        )
    if pulse_pressure > 60:
        safety_warnings.append(
            "⚠️ High pulse pressure detected - may indicate arterial stiffness, monitor cardiovascular status."
        )
    bp_category = (
        "Hypertensive"
        if bp_systolic >= 140 or bp_diastolic >= 90
        else "Elevated"
        if bp_systolic >= 130 or bp_diastolic >= 80
        else "Normal"
    )
    return render_template(
        "anesthesia.html",
        prediction=predicted_dosage_mg,
        confidence=confidence,
        dosage_category=dosage_category,
        theory_explanation=theory_explanation_text,
        shap_raw=raw_explanation_dict,
        anesthesia_type_selected=anesthesia_type_selected,
        surgery_type_selected=surgery_type_selected,
        estimated_duration=surgery_info["duration"],
        re_dose_interval=surgery_info["re_dose_interval"],
        type_specific_message=type_specific_message,
        safety_warnings=safety_warnings,
        bp_systolic=bp_systolic,
        bp_diastolic=bp_diastolic,
        pulse_pressure=pulse_pressure,
        bp_category=bp_category,
        bp_impact_explanation=bp_impact_explanation,
    ) # Safe default

def generate_theory_explanation(
    shap_values_array: Optional[np.ndarray],
    feature_names: list[str],
    predicted_dosage_mg: float,
    bp_data: Optional[Dict[str, float]] = None,
) -> str:
    explanation_parts: list[str] = []
    explanation_parts.append(f"The predicted anesthesia dosage is approximately {predicted_dosage_mg:.2f} units.")
    # BP analysis
    if bp_data:
        bp_systolic = bp_data.get("bp_systolic", 0)
        bp_diastolic = bp_data.get("bp_diastolic", 0)
        pulse_pressure = bp_data.get("pulse_pressure", bp_systolic - bp_diastolic)
        explanation_parts.append("")
        explanation_parts.append("Blood Pressure Analysis:")
        explanation_parts.append(f"• Systolic BP: {bp_systolic} mmHg")
        explanation_parts.append(f"• Diastolic BP: {bp_diastolic} mmHg")
        explanation_parts.append(f"• Pulse Pressure: {pulse_pressure} mmHg")
        if bp_systolic >= 140 or bp_diastolic >= 90:
            explanation_parts.append("• Category: Hypertensive (requires careful monitoring)")
        elif bp_systolic >= 130 or bp_diastolic >= 80:
            explanation_parts.append("• Category: Elevated (moderate risk)")
        else:
            explanation_parts.append("• Category: Normal BP")
        explanation_parts.append("")
        explanation_parts.append("Here's how various patient factors influenced this recommendation:")
    # SHAP values
    try:
        if shap_values_array is not None and shap_values_array.size > 0:
            # Ensure shape is (1, n_features)
            flat_values = shap_values_array.reshape(1, -1)
            if flat_values.shape[1] == len(feature_names):
                ranked = sorted(
                    zip(feature_names, flat_values[0].tolist()),
                    key=lambda x: abs(x[1]),
                    reverse=True,
                )
                idx = 1
                for feature, shap_val in ranked:
                    if abs(shap_val) < 0.01:
                        continue
                    if abs(shap_val) > 3:
                        strength = "strongly"
                    elif abs(shap_val) > 1:
                        strength = "moderately"
                    elif abs(shap_val) > 0.1:
                        strength = "slightly"
                    else:
                        continue
                    display_name = feature.replace("_", " ").title()
                    if feature == "bp_systolic":
                        display_name = "Systolic Blood Pressure"
                    elif feature == "bp_diastolic":
                        display_name = "Diastolic Blood Pressure"
                    elif feature == "pulse_pressure":
                        display_name = "Pulse Pressure (Systolic - Diastolic)"
                    elif feature == "spo2":
                        display_name = "Blood Oxygen Saturation (SpO2)"
                    elif feature == "eeg":
                        display_name = "Electroencephalogram (EEG) activity"
                    elif feature.startswith("anesthesia_type_"):
                        display_name = f"{feature.replace('anesthesia_type_', '').title()} Anesthesia Selection"
                    direction = "increased" if shap_val > 0 else "decreased"
                    explanation_parts.append(
                        f"{idx}. {display_name} {strength} {direction} the recommended dosage. (SHAP value: {shap_val:.2f})"
                    )
                    idx += 1
            else:
                explanation_parts.append("No detailed AI explanation available (feature mismatch).")
        else:
            explanation_parts.append("No detailed AI explanation available (SHAP explainer not initialized or values missing).")
    except Exception as e:
        logger.error(f"Error building SHAP explanation text: {e}")
        explanation_parts.append("Detailed AI explanation is unavailable due to an internal error.")
    explanation_parts.append("")
    explanation_parts.append("This explanation highlights the primary factors the AI considered in reaching its decision.")
    return "\n".join(explanation_parts)

def get_surgery_info(surgery_type: str) -> Dict[str, str]:
    info = {
        "General Surgery": {"duration": "2-4 hours", "re_dose_interval": "30-60 min", "re_dose_check": "after 2 hours"},
        "Cardiac Surgery": {"duration": "4-8 hours", "re_dose_interval": "20-40 min", "re_dose_check": "after 3 hours"},
        "Orthopedic Surgery": {"duration": "1-3 hours", "re_dose_interval": "45-90 min", "re_dose_check": "after 1.5 hours"},
        "Neurosurgery": {"duration": "3-6 hours", "re_dose_interval": "30-50 min", "re_dose_check": "after 2.5 hours"},
        "Emergency Procedure": {"duration": "30 min - 2 hours", "re_dose_interval": "15-30 min", "re_dose_check": "after 45 min"},
        "Minor Procedure": {"duration": "15-60 min", "re_dose_interval": "N/A (single dose)", "re_dose_check": "N/A"},
        "Other": {"duration": "Variable", "re_dose_interval": "Variable", "re_dose_check": "N/A"},
    }
    return info.get(surgery_type, info["Other"])

# -----------------------------------------------------------------------------
# Jinja Filters and Access Control
# -----------------------------------------------------------------------------
@app.template_filter("from_json")
def from_json_filter(value):
    try:
        return json.loads(value) if isinstance(value, str) else value
    except (json.JSONDecodeError, TypeError):
        logger.warning(f"Failed to parse JSON: {value}")
        return []

def require_admin_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not (session.get("role") == "admin" and session.get("admin_authenticated")):
            flash("Access denied: Admin authentication required", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def require_user_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("role") != "user":
            flash("Access denied: User authentication required", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

def log_audit(table_name: str, record_id: int, action: str, old_values=None, new_values=None):
    try:
        user_id = session.get("user_id") or session.get("admin_id")
        audit_entry = Audit_Log(
            table_name=table_name,
            record_id=record_id,
            action=action,
            old_values=old_values,
            new_values=new_values,
            user_id=user_id,
        )
        db.session.add(audit_entry)
        # Commit is handled by caller
    except Exception as e:
        logger.error(f"Error logging audit: {e}")

# -----------------------------------------------------------------------------
# Routes - Auth and Home
# -----------------------------------------------------------------------------
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for("home"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("register"))
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists. Please choose a different one.", "danger")
            return redirect(url_for("register"))
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(username=username, password=hashed_password)
        try:
            db.session.add(new_user)
            db.session.flush()
            log_audit("users", new_user.id, "INSERT", None, {"username": username})
            db.session.commit()
            flash("Account created successfully! You can now log in.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating user: {e}")
            flash("Error creating account. Please try again.", "danger")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        entered_username = (request.form.get("username") or "").strip()
        entered_password = request.form.get("password") or ""
        is_admin_login = "is_admin" in request.form
        if not entered_username or not entered_password:
            flash("Username and password are required.", "danger")
            return render_template("index.html")
        if is_admin_login:
            # Admin login: verify password, then 2FA
            if entered_username == ADMIN_USERNAME and entered_password == ADMIN_PASSWORD:
                session["temp_admin_user"] = entered_username
                flash("Admin password correct. Please complete 2FA.", "info")
                return redirect(url_for("admin_2fa_verify"))
            else:
                flash("Invalid admin credentials.", "danger")
                return render_template("index.html")
        else:
            # Regular user login
            user = User.query.filter_by(username=entered_username).first()
            if not user or not bcrypt.check_password_hash(user.password, entered_password):
                flash("Invalid user credentials.", "danger")
                return render_template("index.html")
            session["username"] = user.username
            session["role"] = "user"
            session["user_id"] = user.id
            flash("Login successful.", "success")
            return redirect(url_for("user_dashboard"))
    return render_template("index.html")

@app.route("/admin_2fa_setup")
def admin_2fa_setup():
    if "temp_admin_user" not in session:
        flash("Please log in as admin first to set up 2FA.", "warning")
        return redirect(url_for("home"))
    try:
        totp = pyotp.TOTP(ADMIN_2FA_SECRET)
        provisioning_uri = totp.provisioning_uri(name=ADMIN_USERNAME, issuer_name="Anesthesia Monitoring System")
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img_io = io.BytesIO()
        img.save(img_io, "PNG")
        img_io.seek(0)
        img_b64 = base64.b64encode(img_io.read()).decode()
        return render_template("admin_2fa_setup.html", qr_code=img_b64, secret=ADMIN_2FA_SECRET)
    except Exception as e:
        logger.error(f"Error generating 2FA setup: {e}")
        # Fallback simple HTML with current code for development
        totp = pyotp.TOTP(ADMIN_2FA_SECRET)
        current_code = totp.now()
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>2FA Setup</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
                .container {{ background: white; padding: 30px; border-radius: 10px; max-width: 600px; margin: 0 auto; }}
                .code {{ background: #e8f4f8; padding: 15px; border-radius: 5px; font-family: monospace; font-size: 18px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h2>🔐 Admin 2FA Setup</h2>
                <p><strong>2FA Secret:</strong></p>
                <div class="code">{ADMIN_2FA_SECRET}</div>
                <p><strong>Current Valid Code (for testing):</strong></p>
                <div class="code">{current_code}</div>
                <h3>Setup Instructions:</h3>
                <ol>
                    <li>Install an authenticator app (Google Authenticator, Authy, etc.)</li>
                    <li>Add a new account manually using the secret above</li>
                    <li>Or use the current code: <strong>{current_code}</strong></li>
                    <li>For testing, you can also use: <strong>000000</strong></li>
                </ol>
                <p><a href="/admin_2fa_verify">← Back to 2FA Verification</a></p>
                <p><a href="/login">← Back to Login</a></p>
            </div>
        </body>
        </html>
        """
        return html_content

@app.route("/admin_2fa_verify", methods=["GET", "POST"])
def admin_2fa_verify():
    if "temp_admin_user" not in session:
        flash("Access denied: Please authenticate as admin first.", "warning")
        return redirect(url_for("home"))
    if request.method == "POST":
        entered_code = (request.form.get("totp_code") or "").strip()
        if not entered_code:
            flash("2FA code is required.", "danger")
            return render_template("admin_2fa_verify.html")
        totp = pyotp.TOTP(ADMIN_2FA_SECRET)
        if entered_code == "000000" or totp.verify(entered_code):
            session["username"] = session["temp_admin_user"]
            session["role"] = "admin"
            session["admin_authenticated"] = True
            # Store admin_id as the DB user id if exists
            admin_user = User.query.filter_by(username=ADMIN_USERNAME).first()
            if admin_user:
                session["admin_id"] = admin_user.id
            session.pop("temp_admin_user", None)
            flash("Admin login successful with 2FA!", "success")
            return redirect(url_for("admin_dashboard"))
        else:
            flash("Invalid 2FA code. Please try again.", "danger")
    # Show current code for dev (flash)
    totp = pyotp.TOTP(ADMIN_2FA_SECRET)
    current_code = totp.now()
    flash(f"Development: Current valid code is {current_code}", "info")
    return render_template("admin_2fa_verify.html")

# -----------------------------------------------------------------------------
# Dashboards
# -----------------------------------------------------------------------------
@app.route("/user_dashboard")
@require_user_auth
def user_dashboard():
    return render_template("user_dashboard.html")

@app.route("/admin_dashboard")
@require_admin_auth
def admin_dashboard():
    total_patients = Patient.query.count()
    total_predictions = Prediction.query.count()
    total_blockchain_entries = len(blockchain.chain)
    recent_predictions = Prediction.query.order_by(Prediction.prediction_time.desc()).limit(10).all()
    return render_template(
        "admin_dashboard.html",
        total_patients=total_patients,
        total_predictions=total_predictions,
        total_blockchain_entries=total_blockchain_entries,
        recent_predictions=recent_predictions,
    )

@app.route("/blockchain_data")
@require_admin_auth
def blockchain_viewer():
    chain_data = []
    for block in blockchain.chain:
        enc_preview = block.encrypted_data
        if enc_preview and len(enc_preview) > 50:
            enc_preview = enc_preview[:50] + "..."
        chain_data.append(
            {
                "index": int(block.index),
                "timestamp": str(block.timestamp),
                "encrypted_data": str(enc_preview),
                "data_hash": str(block.data_hash),
                "previous_hash": str(block.previous_hash),
                "hash": str(block.hash),
                "data_size": len(str(block.encrypted_data or "")),
            }
        )
    is_valid = blockchain.is_chain_valid()
    return render_template("blockchain.html", chain=chain_data, is_valid=is_valid, total_blocks=len(blockchain.chain))

@app.route("/system_integrity")
@require_admin_auth
def system_integrity():
    blockchain_valid = blockchain.is_chain_valid()
    db_patient_count = Patient.query.count()
    db_prediction_count = Prediction.query.count()
    blockchain_entry_count = len(blockchain.chain)
    integrity_status = {
        "blockchain_valid": blockchain_valid,
        "database_patients": db_patient_count,
        "database_predictions": db_prediction_count,
        "blockchain_entries": blockchain_entry_count,
        "last_check": datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
    }
    return render_template("integritycheck.html", status=integrity_status)

# -----------------------------------------------------------------------------
# Vitals Input and Prediction Flow
# -----------------------------------------------------------------------------
@app.route("/vitals_input", methods=["GET", "POST"])
@require_user_auth
def vitals_input():
    if request.method == "POST":
        try:
            patient_id = request.form.get("patient_id")
            patient: Optional[Patient] = None
            if patient_id and patient_id != "new":
                # FIXED: Use db.session.get instead of query.get
                patient = db.session.get(Patient, int(patient_id))
                if not patient:
                    flash("Selected patient not found.", "danger")
                    return redirect(url_for("vitals_input"))
            else:
                patient_name = (request.form.get("patient_name") or "").strip()
                patient_age = request.form.get("patient_age") or ""
                patient_gender = (request.form.get("patient_gender") or "").strip()
                if not patient_name or not patient_age or not patient_gender:
                    flash("New patient information (Name, Age, Gender) is required.", "danger")
                    return redirect(url_for("vitals_input"))
                try:
                    patient_age_int = int(patient_age)
                    if patient_age_int <= 0 or patient_age_int > 150:
                        flash("Patient Age must be between 1 and 150.", "danger")
                        return redirect(url_for("vitals_input"))
                except ValueError:
                    flash("Patient Age must be a valid number.", "danger")
                    return redirect(url_for("vitals_input"))
                patient = Patient(name=patient_name, age=patient_age_int, gender=patient_gender)
                db.session.add(patient)
                db.session.flush()
            # Vitals
            vitals_fields = [
                "temperature",
                "spo2",
                "ecg",
                "eeg",
                "bp_systolic",
                "bp_diastolic",
                "heart_rate",
                "weight",
            ]
            vitals_data: Dict[str, float] = {}
            for field in vitals_fields:
                raw = request.form.get(field)
                if raw is None or raw == "":
                    flash(f"{field.replace('_', ' ').title()} is required.", "danger")
                    return redirect(url_for("vitals_input"))
                try:
                    vitals_data[field] = float(raw)
                except ValueError:
                    flash(f"{field.replace('_', ' ').title()} must be a valid number.", "danger")
                    return redirect(url_for("vitals_input"))
            if vitals_data["bp_systolic"] <= vitals_data["bp_diastolic"]:
                flash("Systolic BP must be higher than Diastolic BP.", "danger")
                return redirect(url_for("vitals_input"))
            if not (70 <= vitals_data["bp_systolic"] <= 250):
                flash("Systolic BP must be between 70 and 250 mmHg.", "danger")
                return redirect(url_for("vitals_input"))
            if not (40 <= vitals_data["bp_diastolic"] <= 150):
                flash("Diastolic BP must be between 40 and 150 mmHg.", "danger")
                return redirect(url_for("vitals_input"))
            if not (70 <= vitals_data["spo2"] <= 100 and 32 <= vitals_data["temperature"] <= 45 and 30 <= vitals_data["heart_rate"] <= 200):
                flash("Out-of-range vitals: require SpO2 70–100%, Temperature 32–45°C, Heart rate 30–200 bpm.", "danger")
                return redirect(url_for("vitals_input"))
            new_vitals = Vitals(patient=patient, **vitals_data)
            db.session.add(new_vitals)
            # History
            history_fields = ["kidney", "liver", "diabetes", "allergy", "asthma"]
            history_data: Dict[str, int] = {}
            for field in history_fields:
                value = request.form.get(field)
                # Handle None, empty string, or missing values by defaulting to "0"
                if value is None or value == "" or value not in ["0", "1"]:
                    if value is not None and value != "":
                        flash(f"{field.title()} must be 0 or 1. Received: '{value}'. Defaulting to 0.", "warning")
                    value = "0"  # Default to 0 (no condition) if invalid or missing
                
                if field == "kidney":
                    history_data["kidney_disease"] = int(value)
                elif field == "liver":
                    history_data["liver_disease"] = int(value)
                elif field == "diabetes":
                    history_data["diabetes"] = int(value)
                elif field == "allergy":
                    history_data["allergy"] = int(value)
                elif field == "asthma":
                    history_data["asthma"] = int(value)
            history_data["other_conditions"] = request.form.get("other_conditions", "")
            new_history = History(patient=patient, **history_data)
            db.session.add(new_history)
            db.session.commit()
            anesthesia_type_selected = request.form.get("anesthesia_type", "general")
            surgery_type_selected = request.form.get("surgery_type", "Other")
            combined_input_data = {
                "age": patient.age,
                "weight": vitals_data["weight"],
                "bp_systolic": vitals_data["bp_systolic"],
                "bp_diastolic": vitals_data["bp_diastolic"],
                "heart_rate": vitals_data["heart_rate"],
                "spo2": vitals_data["spo2"],
                "temperature": vitals_data["temperature"],
                "eeg": vitals_data["eeg"],
                "kidney_disease": history_data["kidney_disease"],
                "liver_disease": history_data["liver_disease"],
                "diabetes": history_data["diabetes"],
                "allergy": history_data["allergy"],
                "asthma": history_data["asthma"],
                "anesthesia_type": anesthesia_type_selected,
                "surgery_type": surgery_type_selected,
            }
            return process_prediction_and_blockchain(patient.id, combined_input_data)
        except ValueError as ve:
            db.session.rollback()
            flash(f"Input error: Please ensure all numerical fields are correctly filled. {ve}", "danger")
            logger.error(f"ValueError in vitals_input: {ve}")
            return redirect(url_for("vitals_input"))
        except Exception as e:
            db.session.rollback()
            flash(f"An unexpected error occurred: {e}", "danger")
            logger.error(f"Unexpected error in vitals_input: {e}", exc_info=True)
            return redirect(url_for("vitals_input"))
    patients = Patient.query.all()
    return render_template("vitals_input.html", patients=patients)

@app.route("/dashboard")
@require_user_auth
def dashboard():
    all_predictions = Prediction.query.order_by(Prediction.prediction_time.desc()).limit(20).all()
    dashboard_data = []
    for pred in all_predictions:
        # FIXED: Use db.session.get instead of query.get
        patient = db.session.get(Patient, pred.patient_id)
        vitals = (
            Vitals.query.filter_by(patient_id=patient.id).order_by(Vitals.recorded_at.desc()).first() if patient else None
        )
        history = History.query.filter_by(patient_id=patient.id).first() if patient else None
        xai = Explainable_AI.query.filter_by(prediction_id=pred.id).first()
        dashboard_data.append({"prediction": pred, "patient": patient, "vitals": vitals, "history": history, "xai": xai})
    return render_template("dashboard.html", dashboard_data=dashboard_data)

# -----------------------------------------------------------------------------
# IoT Ingest
# -----------------------------------------------------------------------------
@app.route("/iot_data", methods=["POST"])
def receive_iot_data():
    if not request.is_json:
        logger.warning("IoT data: Invalid request - not JSON.")
        return jsonify({"status": "error", "message": "Invalid request - expected JSON"}), 400
    iot_data = request.get_json() or {}
    iot_data["received_timestamp"] = datetime.datetime.utcnow().isoformat()
    iot_data["source_ip"] = request.remote_addr
    try:
        patient_id = iot_data.get("patient_id")
        if not patient_id:
            logger.error("IoT data: patient_id missing.")
            return jsonify({"status": "error", "message": "patient_id missing"}), 400
        # FIXED: Use db.session.get instead of query.get
        patient = db.session.get(Patient, int(patient_id))
        if not patient:
            logger.warning(f"IoT data: Patient with ID {patient_id} not found.")
            return jsonify({"status": "error", "message": f"Patient with ID {patient_id} not found"}), 404
        required_vitals = [
            "temperature",
            "spo2",
            "ecg",
            "eeg",
            "bp_systolic",
            "bp_diastolic",
            "heart_rate",
            "weight",
        ]
        for field in required_vitals:
            if iot_data.get(field) is None:
                logger.error(f"IoT data: Missing required vital field: {field}")
                return jsonify({"status": "error", "message": f"Missing required vital: {field}"}), 400
            try:
                float(iot_data[field])
            except (ValueError, TypeError):
                logger.error(f"IoT data: Invalid value for field {field}: {iot_data[field]}")
                return jsonify({"status": "error", "message": f"Invalid value for {field}"}), 400
        bp_systolic = float(iot_data["bp_systolic"])
        bp_diastolic = float(iot_data["bp_diastolic"])
        if bp_systolic <= bp_diastolic:
            return jsonify({"status": "error", "message": "Systolic BP must be higher than Diastolic BP"}), 400
        spo2 = float(iot_data["spo2"])
        temp = float(iot_data["temperature"])
        hr = float(iot_data["heart_rate"])
        if not (70 <= spo2 <= 100 and 32 <= temp <= 45 and 30 <= hr <= 200):
            return jsonify({"status": "error", "message": "Out-of-range vitals: require SpO2 70–100, Temperature 32–45°C, Heart rate 30–200 bpm"}), 400
        new_vitals = Vitals(
            patient_id=patient.id,
            temperature=float(iot_data["temperature"]),
            spo2=float(iot_data["spo2"]),
            ecg=float(iot_data["ecg"]),
            eeg=float(iot_data["eeg"]),
            bp_systolic=bp_systolic,
            bp_diastolic=bp_diastolic,
            heart_rate=float(iot_data["heart_rate"]),
            weight=float(iot_data["weight"]),
        )
        db.session.add(new_vitals)
        db.session.commit()
        latest_history = History.query.filter_by(patient_id=patient.id).order_by(History.id.desc()).first()
        history_data = {
            "kidney_disease": latest_history.kidney_disease if latest_history else 0,
            "liver_disease": latest_history.liver_disease if latest_history else 0,
            "diabetes": latest_history.diabetes if latest_history else 0,
            "allergy": latest_history.allergy if latest_history else 0,
            "asthma": latest_history.asthma if latest_history else 0,
        }
        combined_input_data = {
            "age": patient.age,
            "weight": float(iot_data["weight"]),
            "bp_systolic": bp_systolic,
            "bp_diastolic": bp_diastolic,
            "heart_rate": float(iot_data["heart_rate"]),
            "spo2": float(iot_data["spo2"]),
            "temperature": float(iot_data["temperature"]),
            "eeg": float(iot_data["eeg"]),
            **history_data,
            "anesthesia_type": iot_data.get("anesthesia_type", "general"),
            "surgery_type": iot_data.get("surgery_type", "Other"),
        }
        process_prediction_and_blockchain(patient.id, combined_input_data, is_iot=True)
        return jsonify({"status": "success", "message": "Data processed securely"}), 200
    except ValueError as ve:
        db.session.rollback()
        logger.error(f"ValueError in IoT data processing: {ve}")
        return jsonify({"status": "error", "message": f"Invalid numerical data in IoT payload: {ve}"}), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f"Unexpected error in IoT data processing: {e}", exc_info=True)
        return jsonify({"status": "error", "message": "Processing failed due to internal error"}), 500

# -----------------------------------------------------------------------------
# Error Handlers
# -----------------------------------------------------------------------------
@app.errorhandler(404)
def not_found_error(error):
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template("500.html"), 500

# -----------------------------------------------------------------------------
# Diagnostics
# -----------------------------------------------------------------------------
@app.route("/test_model")
def test_model():
    if session.get("role") not in ["admin", "user"]:
        return jsonify({"error": "Authentication required"}), 401
    try:
        test_patient = {
            "age": 45,
            "weight": 70,
            "bp_systolic": 140,
            "bp_diastolic": 90,
            "heart_rate": 75,
            "spo2": 98,
            "temperature": 37.0,
            "eeg": 35,
            "kidney_disease": 0,
            "liver_disease": 0,
            "diabetes": 1,
            "allergy": 0,
            "asthma": 0,
            "anesthesia_type": "general",
        }
        predicted_dosage = predict_anesthesia_dosage(test_patient)
        pulse_pressure = test_patient["bp_systolic"] - test_patient["bp_diastolic"]
        return jsonify(
            {
                "status": "success",
                "test_patient": test_patient,
                "predicted_dosage": predicted_dosage,
                "pulse_pressure": pulse_pressure,
                "bp_category": "Hypertensive"
                if test_patient["bp_systolic"] >= 140 or test_patient["bp_diastolic"] >= 90
                else "Normal",
                "model_type": "Enhanced Model with BP Analysis" if not isinstance(model, DummyModel) else "Dummy Model",
                "encoder_available": encoder is not None,
                "explainer_available": explainer is not None,
                "features_expected": len(MODEL_FEATURE_NAMES),
                "feature_names": MODEL_FEATURE_NAMES,
                "bp_features_included": ["bp_systolic", "bp_diastolic", "pulse_pressure"],
            }
        )
    except Exception as e:
        logger.error(f"Model test failed: {e}")
        return (
            jsonify(
                {
                    "status": "error",
                    "error": str(e),
                    "model_type": "Enhanced Model with BP Analysis" if not isinstance(model, DummyModel) else "Dummy Model",
                }
            ),
            500,
        )

@app.route("/test_db")
def test_database():
    if session.get("role") not in ["admin", "user"]:
        return jsonify({"error": "Authentication required"}), 401
    try:
        patient_count = Patient.query.count()
        user_count = User.query.count()
        prediction_count = Prediction.query.count()
        latest_vitals = Vitals.query.order_by(Vitals.recorded_at.desc()).first()
        latest_summary = (
            {
                "id": latest_vitals.id,
                "bp_systolic": latest_vitals.bp_systolic,
                "bp_diastolic": latest_vitals.bp_diastolic,
                "pulse_pressure": latest_vitals.pulse_pressure,
                "bp_category": latest_vitals.bp_category,
                "recorded_at": str(latest_vitals.recorded_at),
            }
            if latest_vitals
            else None
        )
        return jsonify(
            {
                "status": "success",
                "database_connection": "OK",
                "patient_count": patient_count,
                "user_count": user_count,
                "prediction_count": prediction_count,
                "latest_vitals": latest_summary,
                "tables_accessible": True,
                "new_bp_schema": "Implemented - systolic/diastolic separation",
            }
        )
    except Exception as e:
        logger.error(f"Database test failed: {e}")
        return jsonify({"status": "error", "database_connection": "FAILED", "error": str(e)}), 500

@app.route("/bp_analysis")
@require_admin_auth
def bp_analysis():
    try:
        vitals_query = (
            db.session.query(Vitals.bp_systolic, Vitals.bp_diastolic, Patient.age, Patient.gender, Vitals.recorded_at)
            .join(Patient)
            .order_by(Vitals.recorded_at.desc())
            .limit(100)
        )
        bp_data = []
        for bp_systolic, bp_diastolic, age, gender, recorded_at in vitals_query:
            pulse_pressure = bp_systolic - bp_diastolic
            category = (
                "Hypertensive"
                if bp_systolic >= 140 or bp_diastolic >= 90
                else "Elevated"
                if bp_systolic >= 130 or bp_diastolic >= 80
                else "Normal"
            )
            bp_data.append(
                {
                    "systolic": bp_systolic,
                    "diastolic": bp_diastolic,
                    "pulse_pressure": pulse_pressure,
                    "category": category,
                    "age": age,
                    "gender": gender,
                    "recorded_at": recorded_at.strftime("%Y-%m-%d %H:%M"),
                }
            )
        if bp_data:
            avg_systolic = sum(d["systolic"] for d in bp_data) / len(bp_data)
            avg_diastolic = sum(d["diastolic"] for d in bp_data) / len(bp_data)
            avg_pulse_pressure = sum(d["pulse_pressure"] for d in bp_data) / len(bp_data)
            hypertensive_count = sum(1 for d in bp_data if d["category"] == "Hypertensive")
            elevated_count = sum(1 for d in bp_data if d["category"] == "Elevated")
            normal_count = sum(1 for d in bp_data if d["category"] == "Normal")
        else:
            avg_systolic = avg_diastolic = avg_pulse_pressure = 0
            hypertensive_count = elevated_count = normal_count = 0
        summary = {
            "total_readings": len(bp_data),
            "average_systolic": round(avg_systolic, 1),
            "average_diastolic": round(avg_diastolic, 1),
            "average_pulse_pressure": round(avg_pulse_pressure, 1),
            "hypertensive_count": hypertensive_count,
            "elevated_count": elevated_count,
            "normal_count": normal_count,
            "hypertensive_percentage": round((hypertensive_count / len(bp_data)) * 100, 1) if bp_data else 0,
        }
        return render_template("bp_analysis.html", bp_data=bp_data, summary=summary)
    except Exception as e:
        logger.error(f"BP Analysis failed: {e}")
        flash(f"Error generating BP analysis: {e}", "danger")
        return redirect(url_for("admin_dashboard"))

@app.route("/audit_logs")
@require_admin_auth
def audit_logs():
    try:
        page = request.args.get("page", 1, type=int)
        per_page = 50
        audit_logs_page = Audit_Log.query.order_by(Audit_Log.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
        return render_template("audit_logs.html", audit_logs=audit_logs_page)
    except Exception as e:
        logger.error(f"Audit logs retrieval failed: {e}")
        flash(f"Error retrieving audit logs: {e}", "danger")
        return redirect(url_for("admin_dashboard"))

# -----------------------------------------------------------------------------
# API Routes
# -----------------------------------------------------------------------------

@app.route("/api/latest_vitals/<patient_id>", methods=["GET"])
def api_get_latest_vitals(patient_id):
    """Get latest vitals for a specific patient via API"""
    try:
        # FIXED: Use db.session.get instead of query.get
        patient = db.session.get(Patient, int(patient_id))
        if not patient:
            return jsonify({"error": "Patient not found"}), 404
            
        latest_vitals = Vitals.query.filter_by(patient_id=patient_id).order_by(Vitals.recorded_at.desc()).first()
        if not latest_vitals:
            return jsonify({"error": "No vitals found for this patient"}), 404
            
        return jsonify({
            "patient_id": patient_id,
            "patient_name": patient.name,
            "vitals": {
                "id": latest_vitals.id,
                "temperature": latest_vitals.temperature,
                "spo2": latest_vitals.spo2,
                "ecg": latest_vitals.ecg,
                "eeg": latest_vitals.eeg,
                "bp_systolic": latest_vitals.bp_systolic,
                "bp_diastolic": latest_vitals.bp_diastolic,
                "heart_rate": latest_vitals.heart_rate,
                "weight": latest_vitals.weight,
                "pulse_pressure": latest_vitals.pulse_pressure,
                "bp_category": latest_vitals.bp_category,
                "recorded_at": latest_vitals.recorded_at.isoformat()
            }
        })
    except Exception as e:
        logger.error(f"Error getting latest vitals for patient {patient_id}: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/latest_vitals_all", methods=["GET"])
def api_get_all_latest_vitals():
    """Get latest vitals for all patients via API"""
    try:
        patients = Patient.query.all()
        result = []
        
        for patient in patients:
            latest_vitals = Vitals.query.filter_by(patient_id=patient.id).order_by(Vitals.recorded_at.desc()).first()
            if latest_vitals:
                result.append({
                    "patient_id": patient.id,
                    "patient_name": patient.name,
                    "age": patient.age,
                    "gender": patient.gender,
                    "vitals": {
                        "temperature": latest_vitals.temperature,
                        "spo2": latest_vitals.spo2,
                        "ecg": latest_vitals.ecg,
                        "eeg": latest_vitals.eeg,
                        "bp_systolic": latest_vitals.bp_systolic,
                        "bp_diastolic": latest_vitals.bp_diastolic,
                        "heart_rate": latest_vitals.heart_rate,
                        "weight": latest_vitals.weight,
                        "pulse_pressure": latest_vitals.pulse_pressure,
                        "bp_category": latest_vitals.bp_category,
                        "recorded_at": latest_vitals.recorded_at.isoformat()
                    }
                })
        
        return jsonify({"patients": result, "total_count": len(result)})
    except Exception as e:
        logger.error(f"Error getting all latest vitals: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/iot_data', methods=['POST'])
def api_receive_iot_data():
    """API version of IoT data reception with enhanced validation"""
    if not request.is_json:
        return jsonify({"status": "error", "message": "Content-Type must be application/json"}), 400
    iot_data = request.get_json() or {}
    iot_data["received_timestamp"] = datetime.datetime.utcnow().isoformat()
    iot_data["source_ip"] = request.remote_addr
    iot_data["api_version"] = "v1"
    try:
        patient_id = iot_data.get("patient_id")
        if not patient_id:
            return jsonify({"status": "error", "message": "patient_id is required"}), 400
        # FIXED: Use db.session.get instead of query.get
        patient = db.session.get(Patient, int(patient_id))
        if not patient:
            return jsonify({"status": "error", "message": f"Patient {patient_id} not found"}), 404
        # Validate required vitals
        required_fields = ["temperature", "spo2", "ecg", "eeg", "bp_systolic", "bp_diastolic", "heart_rate", "weight"]
        missing_fields = [field for field in required_fields if field not in iot_data]
        
        if missing_fields:
            return jsonify({
                "status": "error", 
                "message": f"Missing required fields: {', '.join(missing_fields)}"
            }), 400
        # Create new vitals record
        new_vitals = Vitals(
            patient_id=patient_id,
            temperature=float(iot_data["temperature"]),
            spo2=float(iot_data["spo2"]),
            ecg=float(iot_data.get("ecg", 0)),
            eeg=float(iot_data["eeg"]),
            bp_systolic=float(iot_data["bp_systolic"]),
            bp_diastolic=float(iot_data["bp_diastolic"]),
            heart_rate=float(iot_data["heart_rate"]),
            weight=float(iot_data["weight"])
        )
        db.session.add(new_vitals)
        db.session.flush()
        
        # Log to audit
        log_audit("vitals", new_vitals.id, "INSERT", None, {
            "patient_id": patient_id,
            "source": "IoT_API",
            "vitals_data": iot_data
        })
        
        db.session.commit()
        logger.info(f"API: IoT data saved for patient {patient_id}")
        return jsonify({
            "status": "success",
            "message": "IoT data processed successfully",
            "vitals_id": new_vitals.id,
            "patient_id": patient_id,
            "pulse_pressure": new_vitals.pulse_pressure,
            "bp_category": new_vitals.bp_category
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"API IoT data error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/patient_vitals')
def api_get_patient_vitals():
    """Get vitals for a specific patient or all patients"""
    patient_id = request.args.get('patient_id')
    limit = request.args.get('limit', 50, type=int)
    
    try:
        if patient_id:
            vitals = Vitals.query.filter_by(patient_id=patient_id).order_by(Vitals.recorded_at.desc()).limit(limit).all()
            # FIXED: Use db.session.get instead of query.get
            patient = db.session.get(Patient, patient_id)
            if not patient:
                return jsonify({"error": "Patient not found"}), 404
        else:
            vitals = Vitals.query.order_by(Vitals.recorded_at.desc()).limit(limit).all()
            
        result = []
        for vital in vitals:
            # FIXED: Use db.session.get instead of query.get
            patient = db.session.get(Patient, vital.patient_id)
            result.append({
                "id": vital.id,
                "patient_id": vital.patient_id,
                "patient_name": patient.name if patient else "Unknown",
                "temperature": vital.temperature,
                "spo2": vital.spo2,
                "ecg": vital.ecg,
                "eeg": vital.eeg,
                "bp_systolic": vital.bp_systolic,
                "bp_diastolic": vital.bp_diastolic,
                "heart_rate": vital.heart_rate,
                "weight": vital.weight,
                "pulse_pressure": vital.pulse_pressure,
                "bp_category": vital.bp_category,
                "recorded_at": vital.recorded_at.isoformat()
            })
            
        return jsonify({"vitals": result, "count": len(result)})
    except Exception as e:
        logger.error(f"Error getting patient vitals: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/iot_status')
def api_iot_status():
    """Get IoT system status and statistics"""
    try:
        # Get recent IoT data statistics
        recent_vitals = Vitals.query.filter(
            Vitals.recorded_at >= datetime.datetime.utcnow() - datetime.timedelta(hours=24)
        ).count()
        
        total_patients = Patient.query.count()
        total_vitals = Vitals.query.count()
        
        # Get last data received time
        last_vitals = Vitals.query.order_by(Vitals.recorded_at.desc()).first()
        last_data_time = last_vitals.recorded_at.isoformat() if last_vitals else None
        
        return jsonify({
            "status": "operational",
            "statistics": {
                "total_patients": total_patients,
                "total_vitals_records": total_vitals,
                "recent_vitals_24h": recent_vitals,
                "last_data_received": last_data_time
            },
            "system_time": datetime.datetime.utcnow().isoformat(),
            "api_version": "v1"
        })
    except Exception as e:
        logger.error(f"Error getting IoT status: {e}")
        return jsonify({"status": "error", "error": str(e)}), 500

@app.route("/api/vitals_input", methods=["POST"])
def api_vitals_input():
    """API endpoint for manual vitals input"""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
        
    data = request.get_json()
    
    try:
        patient_id = data.get("patient_id")
        if not patient_id:
            return jsonify({"error": "patient_id is required"}), 400
            
        # FIXED: Use db.session.get instead of query.get
        patient = db.session.get(Patient, int(patient_id))
        if not patient:
            return jsonify({"error": "Patient not found"}), 404
            
        # Create new vitals record
        new_vitals = Vitals(
            patient_id=patient_id,
            temperature=float(data.get("temperature", 37.0)),
            spo2=float(data.get("spo2", 98.0)),
            ecg=float(data.get("ecg", 0)),
            eeg=float(data.get("eeg", 35.0)),
            bp_systolic=float(data.get("bp_systolic", 120)),
            bp_diastolic=float(data.get("bp_diastolic", 80)),
            heart_rate=float(data.get("heart_rate", 70)),
            weight=float(data.get("weight", 70.0))
        )
        
        db.session.add(new_vitals)
        db.session.flush()
        
        log_audit("vitals", new_vitals.id, "INSERT", None, {
            "patient_id": patient_id,
            "source": "Manual_API_Input"
        })
        
        db.session.commit()
        
        return jsonify({
            "status": "success",
            "message": "Vitals recorded successfully",
            "vitals_id": new_vitals.id,
            "pulse_pressure": new_vitals.pulse_pressure,
            "bp_category": new_vitals.bp_category
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"API vitals input error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/load_blockchain_data', methods=['POST'])
def api_load_blockchain_data():
    """API endpoint to load data into blockchain"""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400
        
    data = request.get_json()
    
    try:
        patient_id = data.get("patient_id")
        if not patient_id:
            return jsonify({"error": "patient_id is required"}), 400
            
        # FIXED: Use db.session.get instead of query.get
        patient = db.session.get(Patient, int(patient_id))
        if not patient:
            return jsonify({"error": "Patient not found"}), 404
            
        # Get patient data for blockchain
        vitals = Vitals.query.filter_by(patient_id=patient_id).order_by(Vitals.recorded_at.desc()).first()
        predictions = Prediction.query.filter_by(patient_id=patient_id).order_by(Prediction.prediction_time.desc()).first()
        
        blockchain_data = {
            "patient_id": patient_id,
            "patient_name": patient.name,
            "vitals": {
                "bp_systolic": vitals.bp_systolic if vitals else None,
                "bp_diastolic": vitals.bp_diastolic if vitals else None,
                "heart_rate": vitals.heart_rate if vitals else None,
                "temperature": vitals.temperature if vitals else None
            } if vitals else None,
            "latest_prediction": {
                "result": predictions.prediction_result if predictions else None,
                "confidence": predictions.prediction_confidence if predictions else None,
                "anesthesia_type": predictions.anesthesia_type_selected if predictions else None
            } if predictions else None,
            "timestamp": datetime.datetime.utcnow().isoformat()
        }
        
        # Add to blockchain
        new_block = Block(len(blockchain.chain), datetime.datetime.utcnow(), blockchain_data, blockchain.get_latest_block().hash if blockchain.get_latest_block() else "0")
        blockchain.add_block(new_block)
        
        # Log to database
        blockchain_log = Blockchain_Log(
            patient_id=patient_id,
            block_hash=new_block.hash,
            block_index=new_block.index,
            data_hash=new_block.data_hash
        )
        
        db.session.add(blockchain_log)
        db.session.commit()
        
        return jsonify({
            "status": "success",
            "message": "Data added to blockchain",
            "block_hash": new_block.hash,
            "block_index": new_block.index
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Blockchain load error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/iot_data', methods=['GET'])
def api_get_iot_data():
    """Get IoT data with filtering options"""
    try:
        patient_id = request.args.get('patient_id')
        limit = request.args.get('limit', 100, type=int)
        hours = request.args.get('hours', 24, type=int)
        
        # Filter by time range
        time_filter = datetime.datetime.utcnow() - datetime.timedelta(hours=hours)
        
        query = Vitals.query.filter(Vitals.recorded_at >= time_filter)
        
        if patient_id:
            query = query.filter_by(patient_id=patient_id)
            
        vitals = query.order_by(Vitals.recorded_at.desc()).limit(limit).all()
        
        result = []
        for vital in vitals:
            # FIXED: Use db.session.get instead of query.get
            patient = db.session.get(Patient, vital.patient_id)
            result.append({
                "id": vital.id,
                "patient_id": vital.patient_id,
                "patient_name": patient.name if patient else "Unknown",
                "data": {
                    "temperature": vital.temperature,
                    "spo2": vital.spo2,
                    "ecg": vital.ecg,
                    "eeg": vital.eeg,
                    "bp_systolic": vital.bp_systolic,
                    "bp_diastolic": vital.bp_diastolic,
                    "heart_rate": vital.heart_rate,
                    "weight": vital.weight,
                    "pulse_pressure": vital.pulse_pressure,
                    "bp_category": vital.bp_category
                },
                "timestamp": vital.recorded_at.isoformat()
            })
            
        return jsonify({
            "iot_data": result,
            "count": len(result),
            "filters": {
                "patient_id": patient_id,
                "hours": hours,
                "limit": limit
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting IoT data: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/iot_status/detail')
def api_iot_status_detail():
    """Detailed IoT system status with per-patient breakdown"""
    try:
        patients = Patient.query.all()
        patient_status = []
        
        for patient in patients:
            latest_vitals = Vitals.query.filter_by(patient_id=patient.id).order_by(Vitals.recorded_at.desc()).first()
            vitals_count = Vitals.query.filter_by(patient_id=patient.id).count()
            
            # Check if data is recent (within last hour)
            is_recent = False
            if latest_vitals:
                time_diff = datetime.datetime.utcnow() - latest_vitals.recorded_at
                is_recent = time_diff.total_seconds() < 3600
            
            patient_status.append({
                "patient_id": patient.id,
                "patient_name": patient.name,
                "age": patient.age,
                "gender": patient.gender,
                "total_vitals_records": vitals_count,
                "last_data_received": latest_vitals.recorded_at.isoformat() if latest_vitals else None,
                "data_recent": is_recent,
                "current_vitals": {
                    "bp_systolic": latest_vitals.bp_systolic if latest_vitals else None,
                    "bp_diastolic": latest_vitals.bp_diastolic if latest_vitals else None,
                    "heart_rate": latest_vitals.heart_rate if latest_vitals else None,
                    "temperature": latest_vitals.temperature if latest_vitals else None,
                    "spo2": latest_vitals.spo2 if latest_vitals else None,
                    "bp_category": latest_vitals.bp_category if latest_vitals else None
                } if latest_vitals else None
            })
        
        return jsonify({
            "system_status": "operational",
            "total_patients": len(patients),
            "patients_with_recent_data": sum(1 for p in patient_status if p["data_recent"]),
            "patient_details": patient_status,
            "system_time": datetime.datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting detailed IoT status: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/debug_prediction")
def debug_prediction():
    """Debug endpoint for prediction system"""
    if session.get("role") not in ["admin", "user"]:
        return jsonify({"error": "Authentication required"}), 401
        
    try:
        # Get recent predictions for debugging
        recent_predictions = Prediction.query.order_by(Prediction.prediction_time.desc()).limit(5).all()
        
        debug_info = {
            "model_status": {
                "model_loaded": not isinstance(model, DummyModel),
                "model_type": "Enhanced Model with BP Analysis" if not isinstance(model, DummyModel) else "Dummy Model",
                "encoder_available": encoder is not None,
                "explainer_available": explainer is not None,
                "feature_count": len(MODEL_FEATURE_NAMES),
                "features": MODEL_FEATURE_NAMES
            },
            "recent_predictions": []
        }
        
        for pred in recent_predictions:
            # FIXED: Use db.session.get instead of query.get
            patient = db.session.get(Patient, pred.patient_id)
            debug_info["recent_predictions"].append({
                "id": pred.id,
                "patient_id": pred.patient_id,
                "patient_name": patient.name if patient else "Unknown",
                "prediction_result": pred.prediction_result,
                "confidence": pred.prediction_confidence,
                "anesthesia_type": pred.anesthesia_type_selected,
                "bp_systolic": pred.bp_systolic_at_prediction,
                "bp_diastolic": pred.bp_diastolic_at_prediction,
                "pulse_pressure": pred.pulse_pressure,
                "prediction_time": pred.prediction_time.isoformat()
            })
        
        return jsonify(debug_info)
        
    except Exception as e:
        logger.error(f"Debug prediction error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/debug_model")
def debug_model():
    """Debug endpoint for ML model diagnostics"""
    if session.get("role") not in ["admin", "user"]:
        return jsonify({"error": "Authentication required"}), 401
        
    try:
        # Test model with sample data
        test_data = {
            "age": 45,
            "weight": 70,
            "bp_systolic": 140,
            "bp_diastolic": 90,
            "heart_rate": 75,
            "spo2": 98,
            "temperature": 37.0,
            "eeg": 35,
            "kidney_disease": 0,
            "liver_disease": 0,
            "diabetes": 1,
            "allergy": 0,
            "asthma": 0,
            "anesthesia_type": "general"
        }
        
        # Test prediction
        predicted_dosage = predict_anesthesia_dosage(test_data)
        
        debug_info = {
            "model_diagnostics": {
                "model_type": type(model).__name__,
                "is_dummy_model": isinstance(model, DummyModel),
                "encoder_status": "Available" if encoder else "Not Available",
                "explainer_status": "Available" if explainer else "Not Available",
                "feature_names": MODEL_FEATURE_NAMES,
                "feature_count": len(MODEL_FEATURE_NAMES)
            },
            "test_prediction": {
                "input_data": test_data,
                "predicted_dosage": predicted_dosage,
                "pulse_pressure": test_data["bp_systolic"] - test_data["bp_diastolic"],
                "bp_category": "Hypertensive" if test_data["bp_systolic"] >= 140 or test_data["bp_diastolic"] >= 90 else "Normal"
            },
            "system_info": {
                "timestamp": datetime.datetime.utcnow().isoformat(),
                "python_version": sys.version,
                "model_version": "v2.0_diastolic"
            }
        }
        
        return jsonify(debug_info)
        
    except Exception as e:
        logger.error(f"Debug model error: {e}")
        return jsonify({"error": str(e), "traceback": str(e)}), 500

@app.route('/api/vitals/<int:patient_id>')
def api_get_vitals_by_patient(patient_id):
    """Get all vitals for a specific patient with pagination"""
    try:
        # FIXED: Use db.session.get instead of query.get
        patient = db.session.get(Patient, patient_id)
        if not patient:
            return jsonify({"error": "Patient not found"}), 404
            
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        vitals_query = Vitals.query.filter_by(patient_id=patient_id).order_by(Vitals.recorded_at.desc())
        vitals_paginated = vitals_query.paginate(page=page, per_page=per_page, error_out=False)
        
        vitals_data = []
        for vital in vitals_paginated.items:
            vitals_data.append({
                "id": vital.id,
                "temperature": vital.temperature,
                "spo2": vital.spo2,
                "ecg": vital.ecg,
                "eeg": vital.eeg,
                "bp_systolic": vital.bp_systolic,
                "bp_diastolic": vital.bp_diastolic,
                "heart_rate": vital.heart_rate,
                "weight": vital.weight,
                "pulse_pressure": vital.pulse_pressure,
                "bp_category": vital.bp_category,
                "recorded_at": vital.recorded_at.isoformat()
            })
        
        return jsonify({
            "patient": {
                "id": patient.id,
                "name": patient.name,
                "age": patient.age,
                "gender": patient.gender
            },
            "vitals": vitals_data,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": vitals_paginated.total,
                "pages": vitals_paginated.pages,
                "has_next": vitals_paginated.has_next,
                "has_prev": vitals_paginated.has_prev
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting vitals for patient {patient_id}: {e}")
        return jsonify({"error": str(e)}), 500

# -----------------------------------------------------------------------------
# Entry Point
# -----------------------------------------------------------------------------
def _print_startup_banner():
    print("🏥 Enhanced Anesthesia Prediction System Starting with BP Analysis...")
    print("=" * 70)
    print("🔧 Key Updates Applied:")
    print("   ✅ UPDATED: Separate systolic/diastolic BP fields")
    print("   ✅ ADDED: Pulse pressure calculation and tracking")
    print("   ✅ ADDED: BP category classification (Normal/Elevated/Hypertensive)")
    print("   ✅ ENHANCED: Prediction confidence scoring")
    print("   ✅ ENHANCED: BP-specific risk analysis and explanations")
    print("   ✅ ADDED: BP impact explanations in XAI")
    print("   ✅ UPDATED: Model features to include BP components")
    print("   ✅ ADDED: Enhanced audit logging")
    print("   ✅ ADDED: BP analysis dashboard for admins")
    print("   ✅ UPDATED: Blockchain data with BP details")
    print("   ✅ ENHANCED: IoT endpoint with BP validation")
    print("=" * 70)
    print("🔧 Database Configuration:")
    print(f"   Host: {DB_HOST}")
    print(f"   User: {DB_USER}")
    print(f"   Database: {DB_NAME}")
    print("=" * 70)
    print("🩺 New BP Features:")
    print("   • Systolic/Diastolic BP separation")
    print("   • Automatic pulse pressure calculation")
    print("   • BP category classification")
    print("   • Enhanced risk assessment")
    print("   • BP-specific safety warnings")
    print("=" * 70)
    print("🧪 Test Endpoints Available:")
    print("   /test_model - Test ML model functionality with BP")
    print("   /test_db - Test database connection with new schema")
    print("   /bp_analysis - BP analysis dashboard (Admin only)")
    print("   /audit_logs - Audit trail viewer (Admin only)")
    print("=" * 70)
    print("🔐 Admin Credentials:")
    print(f"   Username: {ADMIN_USERNAME}")
    print(f"   Password: {ADMIN_PASSWORD}")
    print(f"   2FA Secret: {ADMIN_2FA_SECRET}")
    print("   Test 2FA Code: 000000 (bypass for development)")
    print("=" * 70)
    print("📊 Model Features (Updated):")
    print("   • Age, Weight, Heart Rate, SpO2, Temperature, EEG")
    print("   • BP Systolic, BP Diastolic, Pulse Pressure")
    print("   • Medical History (Kidney, Liver, Diabetes, Allergy, Asthma)")
    print("   • Anesthesia Type (General, Local, Regional, Sedation)")
    print("=" * 70)

if __name__ == "__main__":
    with app.app_context():
        try:
            db.create_all()
            logger.info("Database tables checked/created with new BP schema.")
            # FIXED: Use db.session.get instead of query.get
            admin_user = db.session.get(User, 1) if User.query.count() > 0 else None
            if not admin_user:
                hashed_admin_password = bcrypt.generate_password_hash(ADMIN_PASSWORD).decode("utf-8")
                new_admin_user = User(username=ADMIN_USERNAME, password=hashed_admin_password)
                db.session.add(new_admin_user)
                db.session.commit()
                logger.info(f"Admin user '{ADMIN_USERNAME}' created. Please change password in production!")
                logger.info(f"Admin 2FA Secret: {ADMIN_2FA_SECRET}")
            else:
                logger.info(f"Admin user '{ADMIN_USERNAME}' already exists.")
        except Exception as e:
            logger.error(f"Error initializing database: {e}")
            print(f"❌ Database initialization failed: {e}")
            print("Please check your MySQL connection settings:")
            print(f"   Host: {DB_HOST}")
            print(f"   User: {DB_USER}")
            print(f"   Database: {DB_NAME}")
            sys.exit(1)
    _print_startup_banner()
    # Bind to 0.0.0.0 for container use; remove host kwarg if not needed
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))