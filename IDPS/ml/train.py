import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, f1_score
import joblib
import os
from utils.feature_engineering import preprocess_iot_features
from config import ML_MODEL_PATH, DATA_PATH

def load_and_preprocess_data():
    """Load and preprocess NSL-KDD dataset for IoT"""
    df = pd.read_csv(os.path.join(DATA_PATH, "nsl-kdd.csv"))
    
    # IoT-specific feature engineering
    df = preprocess_iot_features(df)
    
    # Map labels to binary classification (0=normal, 1=attack)
    df['label'] = df['label'].apply(lambda x: 0 if x == 'normal' else 1)
    
    # Select IoT-relevant features
    features = df[[
        'protocol_type', 'src_bytes', 'dst_bytes', 'duration',
        'count', 'srv_count', 'dst_host_srv_count', 'dst_host_same_srv_rate'
    ]]
    
    return features, df['label']

def train_lightweight_model(X, y):
    """Train optimized Random Forest for edge deployment"""
    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    
    # Create constrained model for IoT devices
    model = RandomForestClassifier(
        n_estimators=30,       # Reduced number of trees
        max_depth=5,            # Shallow depth for efficiency
        min_samples_split=10,   # Reduce overfitting
        max_features='sqrt',    # Optimize feature usage
        class_weight='balanced',# Handle imbalanced data
        random_state=42,
        n_jobs=-1
    )
    
    # Train model
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    print("Model Evaluation:")
    print(classification_report(y_test, y_pred))
    print(f"F1 Score: {f1_score(y_test, y_pred):.4f}")
    
    return model

def quantize_model(model):
    """Optimize model for edge deployment"""
    # Prune less important trees
    threshold = np.percentile(model.estimators_[0].feature_importances_, 50)
    pruned_estimators = [
        est for est in model.estimators_ 
        if max(est.feature_importances_) > threshold
    ]
    
    # Create quantized model
    quantized = RandomForestClassifier(
        n_estimators=len(pruned_estimators),
        max_depth=model.max_depth,
        random_state=42
    )
    quantized.estimators_ = pruned_estimators
    
    return quantized

def save_model(model, path):
    """Save model with optimization"""
    joblib.dump(model, path, compress=3)
    print(f"Model saved to {path} ({os.path.getsize(path)/1024:.2f} KB)")

if __name__ == "__main__":

    X, y = load_and_preprocess_data()
    
    model = train_lightweight_model(X, y)
    
    quantized_model = quantize_model(model)
    
    save_model(quantized_model, ML_MODEL_PATH)
    
    y_pred_q = quantized_model.predict(X)
    print(f"Quantized model F1: {f1_score(y, y_pred_q):.4f}")