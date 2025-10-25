from flask import Flask, request, jsonify
import joblib
import pandas as pd
import numpy as np

MODEL_FILE = 'rf_model.pkl'
SCALER_FILE = 'scaler.pkl'

app = Flask(__name__)
model = joblib.load(MODEL_FILE)
scaler = joblib.load(SCALER_FILE)

FEATURE_COLS = ["duration", "total_pkts", "total_bytes", "mean_pkt_len", "pkt_rate", "protocol"]

@app.route('/predict', methods=['POST'])
def predict():
    """
    Supports single or batch prediction:
    - Single: {"features": [duration, total_pkts, total_bytes, mean_pkt_len, pkt_rate, protocol]}
      -> {"prediction": 0}
    - Batch: {"flows": [{...}, {...}]} or {"flows": [[...], [...]]}
      -> {"predictions": [0,1,0,...]}
    """
    data = request.get_json(force=True)

    if 'features' in data:
        try:
            features = np.array(data['features']).reshape(1, -1)
            df = pd.DataFrame(features, columns=FEATURE_COLS)
            X_scaled = scaler.transform(df)
            pred = int(model.predict(X_scaled)[0])
            return jsonify({"prediction": pred})
        except Exception as e:
            return jsonify({"error": f"Bad input for 'features' - {e}"}), 400

    if 'flows' in data:
        flows = data['flows']
        if not flows or not isinstance(flows, list):
            return jsonify({"error": "Empty or invalid 'flows' list"}), 400

        try:
            if isinstance(flows[0], dict):
                df = pd.DataFrame(flows)[FEATURE_COLS]
            else:
                df = pd.DataFrame(flows, columns=FEATURE_COLS)

            X_scaled = scaler.transform(df)
            preds = [int(p) for p in model.predict(X_scaled)]
            return jsonify({"predictions": preds})
        except Exception as e:
            return jsonify({"error": f"Prediction failed: {e}"}), 500

    return jsonify({"error": "Invalid payload. Use 'features' or 'flows'."}), 400

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000)
