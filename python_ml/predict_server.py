from flask import Flask, request, jsonify, send_from_directory
import joblib
import pandas as pd
import numpy as np
import os

MODEL_FILE = 'rf_model.pkl'
SCALER_FILE = 'scaler.pkl'
FRONTEND_FOLDER = "../web-dashboard/index.html"

app = Flask(__name__)

model = joblib.load(MODEL_FILE)
scaler = joblib.load(SCALER_FILE)

FEATURE_COLS = ["duration", "total_pkts", "total_bytes", "mean_pkt_len", "pkt_rate", "protocol"]

latest_flows = []

@app.route('/predict', methods=['POST'])
def predict():
    """
    Supports:
    1) Single prediction: {"features": [duration, total_pkts, total_bytes, mean_pkt_len, pkt_rate, protocol]}
    2) Batch prediction: {"flows": [ {...}, {...}, ... ] } or {"flows": [[..], [..], ...]}
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
            return jsonify({"error": f"Bad input for 'features': {e}"}), 400

    if isinstance(data, dict) and 'flows' in data:
        flows = data['flows']
        if not flows or not isinstance(flows, list):
            return jsonify({"error": "Empty or invalid 'flows' list"}), 400

        try:
            if isinstance(flows[0], list) or isinstance(flows[0], tuple):
                df = pd.DataFrame(flows, columns=FEATURE_COLS)
            else:
                df = pd.DataFrame(flows)
                df = df[FEATURE_COLS]
        except Exception as e:
            return jsonify({"error": f"Could not convert flows to DataFrame: {e}"}), 400

        try:
            X_scaled = scaler.transform(df)
            preds = model.predict(X_scaled).tolist()
            preds = [int(p) for p in preds]

            global latest_flows
            latest_flows = []
            for i, row in df.iterrows():
                flow_dict = row.to_dict()
                flow_dict['prediction'] = int(preds[i])
                latest_flows.append(flow_dict)

            return jsonify({"predictions": preds})
        except Exception as e:
            return jsonify({"error": f"Prediction failed: {e}"}), 500

    return jsonify({"error": "Invalid payload. Use 'features' (single) or 'flows' (batch)."}), 400

@app.route('/update_flows', methods=['POST'])
def update_flows():
    """
    Java client posts processed flow results here:
    [
      {"duration":.., "total_pkts":.., "total_bytes":.., "mean_pkt_len":.., "pkt_rate":.., "protocol":.., "prediction":..},
      ...
    ]
    """
    global latest_flows
    try:
        data = request.get_json(force=True)
        if not isinstance(data, list):
            return jsonify({"error": "Expected a list of flow objects"}), 400
        latest_flows = data[-100:] 
        return jsonify({"status": "ok", "count": len(latest_flows)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/get_flows', methods=['GET'])
def get_flows():
    """Return the latest flows with predictions for frontend/dashboard"""
    global latest_flows
    return jsonify({"flows": latest_flows})

@app.route('/')
def serve_dashboard():
    """Serve the dashboard HTML page"""
    return send_from_directory(FRONTEND_FOLDER, 'index.html')

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000)
