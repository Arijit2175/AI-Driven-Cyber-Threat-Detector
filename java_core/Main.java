import java.util.*;

public class Main {

    public static void main(String[] args) throws Exception {

        String csvFile = "../datasets/sample_traffic.csv";
        String serverUrl = "http://127.0.0.1:5000/predict";
        String logFile = "alerts.log";

        PacketCapture capture = new PacketCapture(csvFile);
        ThreatDetector detector = new ThreatDetector(serverUrl);
        AlertLogger logger = new AlertLogger(logFile);

        List<Map<String, String>> flows = capture.readFlows();

        for (Map<String, String> flowMap : flows) {
            double[] features = FeatureExtractor.extractFeatures(flowMap);
            int prediction = detector.predict(features);

            if (prediction == 1) {
                logger.logAlert("Malicious flow detected: " + Arrays.toString(features));
                System.out.println("ALERT! Malicious flow: " + Arrays.toString(features));
            } else {
                System.out.println("Normal flow: " + Arrays.toString(features));
            }
        }

        System.out.println("Detection complete. Alerts logged to " + logFile);
    }
}