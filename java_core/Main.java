import java.io.File;
import java.util.*;

public class Main {

    public static void main(String[] args) throws Exception {

        String csvFile = "../datasets/sample_traffic.csv";
        String serverUrl = "http://127.0.0.1:5000/predict";

        String logsFolderPath = System.getProperty("user.dir") + File.separator + ".." + File.separator + "logs";
        File logsFolder = new File(logsFolderPath);
        if (!logsFolder.exists()) logsFolder.mkdirs();

        String logFilePath = logsFolderPath + File.separator + "alerts.log";
        String maliciousCsvPath = logsFolderPath + File.separator + "malicious_flows.csv";

        AlertLogger logger = new AlertLogger(logFilePath, maliciousCsvPath);
        logger.logAlert("=== New detection session started ===");

        PacketCapture capture = new PacketCapture(csvFile);
        ThreatDetector detector = new ThreatDetector(serverUrl);

        List<Map<String, String>> flows = capture.readFlows();

        for (Map<String, String> flowMap : flows) {
            double[] features = FeatureExtractor.extractFeatures(flowMap);
            int prediction = detector.predict(features);

            if (prediction == 1) {
                logger.logMalicious(features); 
                System.out.println("ALERT! Malicious flow: " + Arrays.toString(features));
            } else {
                logger.logAlert("Normal flow: " + Arrays.toString(features));
                System.out.println("Normal flow: " + Arrays.toString(features));
            }
        }

        System.out.println("Detection complete. Alerts logged to " + logFilePath);
        System.out.println("Malicious flows saved to " + maliciousCsvPath);
    }
}
