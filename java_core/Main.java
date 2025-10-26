import java.io.*;
import java.net.*;
import java.util.*;
import com.google.gson.*; 

// The main class to run the AI-driven cyber threat detection system.
public class Main {

    public static void main(String[] args) throws Exception {

        String csvFile = "../datasets/sample_traffic.csv";
        String serverUrl = "http://127.0.0.1:5000/predict";

        File logsFolder = new File("../logs");
        if (!logsFolder.exists()) logsFolder.mkdirs();

        File logFile = new File(logsFolder, "alerts.log");
        AlertLogger logger = new AlertLogger(logFile.getAbsolutePath());
        logger.logAlert("=== New detection session started ===");

        File maliciousCsv = new File(logsFolder, "malicious_flows.csv");
        if (!maliciousCsv.exists()) {
            try (PrintWriter pw = new PrintWriter(new FileWriter(maliciousCsv, true))) {
                pw.println("duration,total_pkts,total_bytes,mean_pkt_len,pkt_rate,protocol");
            }
        }

        PacketCapture capture = new PacketCapture(csvFile);
        ThreatDetector detector = new ThreatDetector(serverUrl);

        List<Map<String, String>> flows = capture.readFlows();
        List<double[]> featureList = new ArrayList<>(flows.size());

        for (Map<String, String> flowMap : flows)
            featureList.add(FeatureExtractor.extractFeatures(flowMap));

        List<Integer> preds = detector.predictBatch(featureList);

        for (int i = 0; i < featureList.size(); i++) {
            double[] features = featureList.get(i);
            int prediction = preds.get(i);

            if (prediction == 1) {
                logger.logAlert("Malicious flow detected: " + Arrays.toString(features));
                System.out.println("ALERT! Malicious flow: " + Arrays.toString(features));
                try (PrintWriter pw = new PrintWriter(new FileWriter(maliciousCsv, true))) {
                    pw.println(features[0] + "," + features[1] + "," + features[2] + "," +
                               features[3] + "," + features[4] + "," + features[5]);
                }
            } else {
                logger.logAlert("Normal flow: " + Arrays.toString(features));
                System.out.println("Normal flow: " + Arrays.toString(features));
            }
        }

        List<Map<String, Object>> resultPayload = new ArrayList<>();
        for (int i = 0; i < featureList.size(); i++) {
            double[] f = featureList.get(i);
            int pred = preds.get(i);

            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("duration", f[0]);
            entry.put("total_pkts", f[1]);
            entry.put("total_bytes", f[2]);
            entry.put("mean_pkt_len", f[3]);
            entry.put("pkt_rate", f[4]);
            entry.put("protocol", f[5]);
            entry.put("prediction", pred);

            resultPayload.add(entry);
        }

        try {
            URL updateUrl = new URL("http://127.0.0.1:5000/update_flows");
            HttpURLConnection conn = (HttpURLConnection) updateUrl.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            conn.setDoOutput(true);

            Gson gson = new Gson();
            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = gson.toJson(resultPayload).getBytes("utf-8");
                os.write(input, 0, input.length);
            }

            int responseCode = conn.getResponseCode();
            if (responseCode == 200)
                System.out.println("✅ Flow data sent to dashboard successfully.");
            else
                System.out.println("⚠️ Failed to update dashboard. HTTP " + responseCode);
        } catch (Exception e) {
            System.err.println("Error sending data to dashboard: " + e.getMessage());
        }

        System.out.println("Detection complete. Alerts logged to " + logFile.getAbsolutePath());
        System.out.println("Malicious flows saved to " + maliciousCsv.getAbsolutePath());
    }
}
