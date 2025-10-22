from flask import Flask, request, jsonify
import joblib
import numpy as np

MODEL_FILE = 'rf_model.pkl'
SCALER_FILE = 'scaler.pkl'

app = Flask(__name__)
model = joblib.load(MODEL_FILE)
scaler = joblib.load(SCALER_FILE)

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    if 'features' not in data:
        return jsonify({"error":"Missing 'features' key"}), 400

    features = np.array(data['features']).reshape(1, -1)
    features_scaled = scaler.transform(features)
    pred = model.predict(features_scaled)[0]
    return jsonify({"prediction": int(pred)})

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=5000)
