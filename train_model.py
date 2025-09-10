# train_model_csv_only.py
import os
import sys
import numpy as np
import pandas as pd
import joblib
import matplotlib.pyplot as plt
import warnings
warnings.filterwarnings('ignore')

from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split, cross_val_score, KFold
from sklearn.preprocessing import OneHotEncoder
from sklearn.metrics import mean_absolute_error, r2_score, mean_squared_error

# Optional explainability
try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False

# Directories
os.makedirs("models", exist_ok=True)
os.makedirs("explanation", exist_ok=True)

print("🏥 Anesthesia Dosage Prediction - CSV Mode")
print("=" * 50)

# CSV candidates - look for these files
CSV_CANDIDATES = [
    "medical_dataset_with_anesthesia_dosage.csv",
    "Anesthesia_Simulated_Dataset_v2_with_dosage.csv",
    "anesthesia_dataset.csv",
    "dataset.csv"
]

def load_csv_data():
    """Load data from CSV file"""
    print("🔍 Looking for CSV files...")
    
    for csv_file in CSV_CANDIDATES:
        if os.path.exists(csv_file):
            print(f"✅ Found: {csv_file}")
            try:
                df = pd.read_csv(csv_file)
                if df.empty:
                    print(f"⚠️ {csv_file} is empty, trying next...")
                    continue
                print(f"📊 Loaded {len(df)} rows, {len(df.columns)} columns")
                return df, csv_file
            except Exception as e:
                print(f"❌ Failed to load {csv_file}: {e}")
                continue
    
    # List all CSV files in directory
    csv_files = [f for f in os.listdir('.') if f.endswith('.csv')]
    if csv_files:
        print(f"📁 Found CSV files: {csv_files}")
        print("Please rename one to 'dataset.csv' or update CSV_CANDIDATES")
    else:
        print("❌ No CSV files found in current directory")
    
    return None, None

def clean_column_names(df):
    """Clean and standardize column names"""
    df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_').str.replace('-', '_')
    
    # Common column mappings
    column_mapping = {
        'heartrate': 'heart_rate',
        'systolic_bp': 'bp_systolic', 
        'diastolic_bp': 'bp_diastolic',
        'anesthesia_dosage_(mg/kg)': 'anesthesia_dosage',
        'anesthesia_dosage_mg': 'anesthesia_dosage'
    }
    
    df = df.rename(columns=column_mapping)
    return df

def prepare_data(df):
    """Prepare data for training"""
    print("\n📝 Data preparation...")
    
    # Find target column
    target_candidates = ['anesthesia_dosage', 'dosage', 'anesthesia_dosage_mg']
    target_col = None
    
    for col in target_candidates:
        if col in df.columns:
            target_col = col
            break
    
    if target_col is None:
        print(f"❌ Target column not found. Available columns: {list(df.columns)}")
        return None, None, None, None
    
    print(f"🎯 Target column: {target_col}")
    
    # Define feature columns
    numeric_features = []
    binary_features = []
    
    # Check for numeric features
    possible_numeric = ['age', 'weight', 'heart_rate', 'bp_systolic', 'bp_diastolic', 
                       'spo2', 'temperature', 'ecg', 'eeg']
    
    for col in possible_numeric:
        if col in df.columns:
            numeric_features.append(col)
    
    # Check for binary/categorical features  
    possible_binary = ['diabetes', 'kidney_disease', 'liver_disease', 'allergy', 'asthma']
    
    for col in possible_binary:
        if col in df.columns:
            binary_features.append(col)
    
    print(f"📊 Numeric features ({len(numeric_features)}): {numeric_features}")
    print(f"📊 Binary features ({len(binary_features)}): {binary_features}")
    
    if not numeric_features and not binary_features:
        print("❌ No recognizable features found!")
        return None, None, None, None
    
    # Process numeric features
    for col in numeric_features:
        df[col] = pd.to_numeric(df[col], errors='coerce')
        df[col] = df[col].fillna(df[col].median())
    
    # Process binary features (Yes/No -> 1/0)
    for col in binary_features:
        if df[col].dtype == 'object':
            df[col] = df[col].map({'Yes': 1, 'No': 0, 'yes': 1, 'no': 0, 'Y': 1, 'N': 0})
        df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
    
    # Handle anesthesia type for encoding
    if 'anesthesia_type' not in df.columns:
        df['anesthesia_type'] = 'General'
    
    df['anesthesia_type'] = df['anesthesia_type'].fillna('General').astype(str)
    
    # Prepare target
    y = pd.to_numeric(df[target_col], errors='coerce')
    valid_idx = ~y.isna()
    
    print(f"✅ Valid samples: {valid_idx.sum()}/{len(df)}")
    
    return df[valid_idx], numeric_features + binary_features, target_col, y[valid_idx]

def main():
    # Load data
    data, csv_file = load_csv_data()
    if data is None:
        print("\n❌ No CSV data found. Please ensure you have a CSV file in the current directory.")
        sys.exit(1)
    
    # Clean column names
    data = clean_column_names(data)
    
    # Show first few rows and column info
    print(f"\n📋 Dataset Info:")
    print(f"   Shape: {data.shape}")
    print(f"   Columns: {list(data.columns)}")
    
    # Prepare data
    clean_data, feature_cols, target_col, y = prepare_data(data)
    if clean_data is None:
        sys.exit(1)
    
    # Create feature matrix
    X_numeric = clean_data[feature_cols]
    
    # Encode anesthesia type
    encoder = OneHotEncoder(sparse_output=False, handle_unknown='ignore', drop='first')
    anesthesia_encoded = encoder.fit_transform(clean_data[['anesthesia_type']])
    anesthesia_cols = encoder.get_feature_names_out(['anesthesia_type'])
    
    # Combine features
    X = np.column_stack([X_numeric.values, anesthesia_encoded])
    feature_names = feature_cols + list(anesthesia_cols)
    
    print(f"🔢 Final feature matrix: {X.shape}")
    
    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Train model
    print(f"\n🤖 Training Random Forest...")
    print(f"   Training samples: {len(X_train)}")
    print(f"   Test samples: {len(X_test)}")
        
    model = RandomForestRegressor(
        n_estimators=100,
        max_depth=10,
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate
    train_pred = model.predict(X_train)
    test_pred = model.predict(X_test)
    
    train_r2 = r2_score(y_train, train_pred)
    test_r2 = r2_score(y_test, test_pred)
    train_mae = mean_absolute_error(y_train, train_pred)
    test_mae = mean_absolute_error(y_test, test_pred)
    
    print(f"\n📈 Results:")
    print(f"   Train R²: {train_r2:.4f}")
    print(f"   Test R²:  {test_r2:.4f}")
    print(f"   Train MAE: {train_mae:.4f}")
    print(f"   Test MAE:  {test_mae:.4f}")
    
    # Feature importance
    importance_df = pd.DataFrame({
        'feature': feature_names,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print(f"\n🎯 Top 5 Important Features:")
    print(importance_df.head().to_string(index=False))
    
    # Save model
    joblib.dump(model, "models/anesthesia_model.pkl")
    joblib.dump(encoder, "models/anesthesia_type_encoder.pkl")
    
    # Save feature info
    feature_info = {
        'feature_columns': feature_cols,
        'feature_names': feature_names,
        'target_column': target_col
    }
    joblib.dump(feature_info, "models/feature_info.pkl")
    
    print(f"\n💾 Model saved to models/")
    
    # Save predictions
    clean_data['predicted_dosage'] = model.predict(X)
    clean_data.to_csv("predictions.csv", index=False)
    print(f"📊 Predictions saved to predictions.csv")
    
    print(f"\n✅ Training complete!")
    print(f"📋 Summary: {len(clean_data)} samples, {len(feature_names)} features, Test R²={test_r2:.3f}")

if __name__ == "__main__":
    main()