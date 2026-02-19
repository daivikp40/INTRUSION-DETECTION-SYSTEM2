# train_model.py
import sqlite3
import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier
import os

def train():
    print("🔄 Preparing training data...")
    
    # Since our 'alerts.db' only stores text messages and not the raw packet statistics 
    # (packet_rate, unique_ports, etc.) required for ML, we will ALWAYS generate 
    # a clean synthetic dataset to train the model's baseline behavior.
    
    print("⚠️ Generating synthetic training data for baseline model...")
    
    # 1. Define the training patterns
    # These numbers represent "Normal" vs "Attack" behavior
    data = {
        'packet_rate': [
            10, 12, 15, 8, 20, 5, 11, 14, 9, 13,       # Normal
            100, 120, 200, 80, 300, 150, 250, 400,     # DoS / Flood
            50, 60, 45, 55                             # Heavy Traffic
        ],
        'unique_ports': [
            1, 1, 2, 1, 1, 2, 1, 1, 1, 1,              # Normal
            20, 15, 50, 10, 100, 30, 80, 120,          # Port Scan
            5, 3, 4, 6                                 # Normal-ish
        ],
        'failed_logins': [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 1,              # Normal
            10, 5, 20, 2, 50, 8, 15, 30,               # Brute Force
            1, 2, 0, 1                                 # User Mistake
        ],
        # Label: 0 = Normal, 1 = Malicious
        'is_malicious': [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0,              # Normal
            1, 1, 1, 1, 1, 1, 1, 1,                    # Attacks
            0, 0, 0, 0                                 # Edge cases
        ]
    }

    # 2. Create DataFrame and expand it
    df = pd.DataFrame(data)
    # Duplicate the data to simulate a larger dataset for better stability
    df = pd.concat([df]*50, ignore_index=True)

    # 3. separate Features (X) and Target (y)
    X = df[['packet_rate', 'unique_ports', 'failed_logins']]
    y = df['is_malicious']

    # 4. Train Random Forest Model
    print("🚀 Training Random Forest model...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)

    # 5. Save the model
    with open("ids_model.pkl", "wb") as f:
        pickle.dump(clf, f)
    
    print("✅ Model trained and saved as 'ids_model.pkl'")

if __name__ == "__main__":
    train()