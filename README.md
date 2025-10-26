# 🧠 AI Cyber Threat Dashboard

A lightweight, real-time dashboard built to visualize network flow data and detect potential cyber threats using AI predictions.  
The dashboard presents both tabular and graphical insights into network flows and allows you to monitor malicious vs. normal activity in real time.

---

## 🚀 Features

- 📊 **Real-Time Flow Updates** – Displays new network flows one at a time in the table.
- 🔄 **Live Chart Updates** – Line chart automatically updates to reflect the most recent data.
- ⚙️ **AI Prediction Display** – Shows model predictions for each flow (Normal / Malicious).
- 🌗 **Light & Dark Mode** – Easily switch between light and dark themes.
- 📁 **Export Functionality** – Export all displayed flow data to a CSV file.
- 🧭 **Collapsible Sidebar** – Transparent sidebar that can expand or collapse for better visibility.
- 💡 **Responsive Layout** – Chart and table displayed side-by-side for clear, modern visualization.

---

## 🗂️ Project Structure

AI-Driven-Cyber-Threat-Detector
```
│
├── web-dashboard # Main dashboard page
├── datasets # Sample dataset or dataset you want to use
├── java_core # Java components
├── logs # Output logs are saved here after scanning the flows
├── python_ml # Python components (Training the model saves it in the project root)
└── README.md # Project documentation
```

---

## ⚙️ System Workflow

### 🧩 Step-by-Step Process

1. **Packet Capture (Java):**
   - `packetcapture.java` continuously monitors live network traffic.
   - Extracted packets are formatted into flow-based records.

2. **Feature Extraction:**
   - `featureextractor.java` computes attributes like:
     - Flow duration  
     - Packet count  
     - Bytes per second  
     - Mean packet size  
     - Protocol and source/destination ports

3. **Threat Detection (Python):**
   - `predict_server.py` runs a lightweight Python service exposing an ML model via sockets or REST.
   - Java sends extracted flow features to this server.
   - The model (trained using `train_model.py`) returns a label: **Normal** or **Malicious**.

4. **Logging (Java):**
   - If malicious activity is detected, it is recorded in:
     - `logs/alerts.log` (human-readable)
     - `logs/malicious_flows.csv` (structured for analysis)

5. **Visualization (Web Dashboard):**
   - The **web-dashboard** displays:
     - Total flows scanned  
     - Malicious and normal flow counts  
     - Real-time line/bar charts  
     - Live updating table with color-coded rows  

---

## 🧠 AI Model

The ML model can be trained using **`python_ml/train_model.py`** on `dataset/sample_traffic.csv`.  
Typical features include flow duration, byte count, and packet rates.  
You can use models like Random Forest, SVM, or a lightweight neural network.

Example training command:

```
cd python_ml
python train_model.py
```

This will generate and save a trained model file (e.g., model.pkl), which predict_server.py loads for live inference.

---

