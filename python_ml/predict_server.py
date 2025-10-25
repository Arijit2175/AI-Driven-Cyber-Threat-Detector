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
    Supports two input formats:
    1) Single prediction (backward compatible):
       {"features": [duration, total_pkts, total_bytes, mean_pkt_len, pkt_rate, protocol]}
       -> {"prediction": 0}

    2) Batch prediction (new):
       {"flows": [ { "duration":.., "total_pkts":.., ... }, {...}, ... ]}
       or
       {"flows": [ [duration, total_pkts, ...], [...], ... ] }
       -> {"predictions": [0,1,0,...]}
    """
    data = request.get_json(force=True)

    if isinstance(data, dict) and 'features' in data:
        try:
            features = np.array(data['features']).reshape(1, -1)
            df = pd.DataFrame(features, columns=FEATURE_COLS)
            X_scaled = scaler.transform(df)
            pred = int(model.predict(X_scaled)[0])
            return jsonify({"prediction": pred})
        except Exception as e:
            return jsonify({"error": f"Bad input for 'features' - {str(e)}"}), 400

    if isinstance(data, dict) and 'flows' in data:
        flows = data['flows']
        if not isinstance(flows, list) or len(flows) == 0:
            return jsonify({"error": "Empty or invalid 'flows' list"}), 400

        if isinstance(flows[0], list) or isinstance(flows[0], tuple):
            try:
                df = pd.DataFrame(flows, columns=FEATURE_COLS)
            except Exception as e:
                return jsonify({"error": f"Could not convert flows (array) to dataframe: {e}"}), 400
        else:
            try:
                df = pd.DataFrame(flows)
                df = df[FEATURE_COLS]
            except Exception as e:
                return jsonify({"error": f"Could not convert flows (dict) to dataframe: {e}"}), 400

        try:
            X_scaled = scaler.transform(df)
            preds = model.predict(X_scaled).tolist()
            # ensure ints
            preds = [int(p) for p in preds]
            return jsonify({"predictions": preds})
        except Exception as e:
            return jsonify({"error": f"Prediction failed: {e}"}), 500

    return jsonify({"error": "Invalid payload. Use 'features' (single) or 'flows' (batch)."}), 400

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000)
