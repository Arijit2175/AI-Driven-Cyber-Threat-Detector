import java.io.*;
import java.util.*;

public class Main {

    public static void main(String[] args) throws Exception {

        String csvFile = "../datasets/sample_traffic.csv";
        String serverUrl = "http://127.0.0.1:5000/predict";

        String logFile = System.getProperty("user.dir") + File.separator + ".." + File.separator + "logs" + File.separator + "alerts.log";
        AlertLogger logger = new AlertLogger(logFile);

        PacketCapture capture = new PacketCapture(csvFile);
        ThreatDetector detector = new ThreatDetector(serverUrl);

        logger.logAlert("=== New detection session started ===");

        List<Map<String, String>> flows = capture.readFlows();

        for (Map<String, String> flowMap : flows) {
            double[] features = FeatureExtractor.extractFeatures(flowMap);
            int prediction = detector.predict(features);

            if (prediction == 1) {
                logger.logAlert("Malicious flow detected: " + Arrays.toString(features));
                System.out.println("ALERT! Malicious flow: " + Arrays.toString(features));
            } else {
                logger.logAlert("Normal flow: " + Arrays.toString(features));
                System.out.println("Normal flow: " + Arrays.toString(features));
            }
        }

        System.out.println("Detection complete. Alerts logged to " + logFile);
    }
}
