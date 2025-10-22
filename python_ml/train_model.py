import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import os

FLOW_CSV = '../datasets/sample_traffic.csv'
MODEL_FILE = 'rf_model.pkl'
SCALER_FILE = 'scaler.pkl'
PROTOCOL_ENCODER_FILE = 'protocol_label_encoder.pkl'

def main():
    if not os.path.exists(FLOW_CSV):
        print("Flow CSV not found:", FLOW_CSV)
        return

    df = pd.read_csv(FLOW_CSV)
    print("Loaded flow CSV:", df.shape)

    le = LabelEncoder()
    df['protocol'] = le.fit_transform(df['protocol'])
    joblib.dump(le, PROTOCOL_ENCODER_FILE)
    print("Saved protocol encoder.")

    X = df[['duration','total_pkts','total_bytes','mean_pkt_len','pkt_rate','protocol']]
    y = df['label']

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    joblib.dump(scaler, SCALER_FILE)
    print("Saved scaler.")

    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("Classification Report:\n", classification_report(y_test, y_pred))
    print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

    joblib.dump(clf, MODEL_FILE)
    print("Saved model:", MODEL_FILE)

if __name__ == "__main__":
    main()
