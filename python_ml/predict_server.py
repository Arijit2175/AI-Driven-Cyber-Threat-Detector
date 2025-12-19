from flask import Flask, request, jsonify, send_from_directory
import joblib
import pandas as pd
import numpy as np
import os

# Load ML model and scaler
MODEL_FILE = 'rf_model.pkl'
SCALER_FILE = 'scaler.pkl'
FRONTEND_FOLDER = os.path.join(os.path.dirname(__file__), '..', 'web-dashboard')

app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path='')

model = joblib.load(MODEL_FILE)
scaler = joblib.load(SCALER_FILE)
protocol_encoder = None
if os.path.exists(PROTOCOL_ENCODER_FILE):
    try:
        protocol_encoder = joblib.load(PROTOCOL_ENCODER_FILE)
    except Exception:
        protocol_encoder = None

FEATURE_COLS = ["duration", "total_pkts", "total_bytes", "mean_pkt_len", "pkt_rate", "protocol"]

latest_flows = []

# Prediction endpoint
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
            # Map numeric protocol codes to names for encoder
            if protocol_encoder is not None:
                def map_proto(v):
                    try:
                        iv = int(v)
                        if iv == 6:
                            return 'TCP'
                        elif iv == 17:
                            return 'UDP'
                        elif iv == 1:
                            return 'ICMP'
                        else:
                            return 'OTHER'
                    except Exception:
                        return str(v).upper()
                df['protocol'] = df['protocol'].apply(map_proto)
                # Encode using saved label encoder from training
                try:
                    df['protocol'] = protocol_encoder.transform(df['protocol'])
                except Exception:
                    pass
            X_scaled = scaler.transform(df)
            pred = int(model.predict(X_scaled)[0])
            proba = model.predict_proba(X_scaled)
            score = float(proba[0][1])  # Probability of malicious class
            return jsonify({"prediction": pred, "score": score})
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
            # Map numeric protocol codes to names and encode
            if protocol_encoder is not None:
                def map_proto(v):
                    try:
                        iv = int(v)
                        if iv == 6:
                            return 'TCP'
                        elif iv == 17:
                            return 'UDP'
                        elif iv == 1:
                            return 'ICMP'
                        else:
                            return 'OTHER'
                    except Exception:
                        return str(v).upper()
                df['protocol'] = df['protocol'].apply(map_proto)
                try:
                    df['protocol'] = protocol_encoder.transform(df['protocol'])
                except Exception:
                    pass
        except Exception as e:
            return jsonify({"error": f"Could not convert flows to DataFrame: {e}"}), 400

        try:
            X_scaled = scaler.transform(df)
            preds = model.predict(X_scaled).tolist()
            preds = [int(p) for p in preds]
            
            # Get probability scores (confidence for malicious class)
            proba = model.predict_proba(X_scaled)
            scores = [float(proba[i][1]) for i in range(len(proba))]  # Prob of class 1 (malicious)

            global latest_flows
            latest_flows = []
            for i, row in df.iterrows():
                flow_dict = row.to_dict()
                flow_dict['prediction'] = int(preds[i])
                flow_dict['score'] = scores[i]
                latest_flows.append(flow_dict)

            return jsonify({"predictions": preds, "scores": scores})
        except Exception as e:
            return jsonify({"error": f"Prediction failed: {e}"}), 500

    return jsonify({"error": "Invalid payload. Use 'features' (single) or 'flows' (batch)."}), 400

# Update flows endpoint
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

# Get flows endpoint
@app.route('/get_flows', methods=['GET'])
def get_flows():
    """Return the latest flows with predictions for frontend/dashboard"""
    global latest_flows
    return jsonify({"flows": latest_flows})

# Serve dashboard
@app.route('/')
def serve_dashboard():
    """Serve the dashboard HTML page"""
    return send_from_directory(FRONTEND_FOLDER, 'index.html')

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000)
