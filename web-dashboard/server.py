from flask import Flask, jsonify
import pandas as pd
import os

app = Flask(__name__)
LOGS_FOLDER = "../logs"
MALICIOUS_CSV = os.path.join(LOGS_FOLDER, "malicious_flows.csv")

@app.route("/get_flows", methods=["GET"])
def get_flows():
    if not os.path.exists(MALICIOUS_CSV):
        return jsonify([])
    df = pd.read_csv(MALICIOUS_CSV)
    df["prediction"] = 1  
    return jsonify(df.to_dict(orient="records"))

if __name__ == "__main__":
    app.run(port=5001)
