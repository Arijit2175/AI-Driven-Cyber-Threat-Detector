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

## 🐍 Python ML Server Setup

1. Navigate to the ML Backend:
```
cd python_ml
```

2. Install dependencies:
```
pip install scikit-learn pandas flask joblib
```

3. Start the prediction server:
```
python predict_server.py
```

4. The server listens on a local port(eg., `http://127.0.0.1:5000`) for feature data sent from java.

---

## ☕ Java Core Setup

1. Navigate to `java_core`:
```
cd java_core
```

2. Compile all java files:
We need to have the gson-x.x.x.jar file in java_core folder for the java components to be compiled
```
javac -cp ".;gson-x.x.x.jar" *.java
```

3. Run the main module:
```
java -cp ".;gson-x.x.x.jar" Main
```

4. The java program:
      - Captures packets
      - Extract features
      - Sends features to Python for classification
      - Logs detected malicious activity
      - Optionally pushes results to the dashboard

---

## 🌐 Web Dashboard Setup

1. Navigate to the dashboard folder:
```
cd web-dashboard
```

2. Open `index.html` in your browser.

3. The dashboard will:
- Display live-updating tables and charts
- Show total flows scanned, alerts, and threat trends
- Automatically update visuals based on `malicious_flows.csv` or simulated live feed in `script.js`
      
---

## 📈 Dashboard Features

| Component               | Description                                                                          |
| ----------------------- | ------------------------------------------------------------------------------------ |
| **Table View**          | Displays flow-by-flow results in real time.                                          |
| **Chart View**          | Line chart dynamically shows changing malicious vs normal ratio.                     |
| **Sidebar**             | Displays quick stats (Total, Malicious, Normal) and controls (Export, Theme toggle). |
| **CSV Export**          | One-click export of current flow data to `.csv`.                                     |
| **Theme Toggle**        | Switch between Light and Dark modes.                                                 |
| **Collapsible Sidebar** | Transparent compact sidebar with toggle button.                                      |

---

📤 Log & Output Files

| File                  | Purpose                                 |
| --------------------- | --------------------------------------- |
| `alerts.log`          | Text log of all detected threats        |
| `malicious_flows.csv` | Structured CSV log for further analysis |
| `sample_traffic.csv`  | Dataset for training/testing model      |

 ---

## 🔧 Dependencies

1. Python:
    - scikit-learn
    - pandas
    - flask
    - joblib

2. Java:
    - Java SE 8+
    - Gson / JSON-simple for JSON parsing
    - (Optional) Jpcap / Pcap4J for packet capture

3. Frontend:
    - Chart.js
    - Vanilla HTML, CSS, JavaScript

---

