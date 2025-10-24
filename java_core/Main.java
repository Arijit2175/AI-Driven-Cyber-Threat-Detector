import java.io.File;
import java.util.*;

public class Main {

    public static void main(String[] args) throws Exception {

        String csvFile = ".." + File.separator + "datasets" + File.separator + "sample_traffic.csv";
        String serverUrl = "http://127.0.0.1:5000/predict";

        String logFolderPath = ".." + File.separator + "logs";
        File logFolder = new File(logFolderPath);
        if (!logFolder.exists()) {
            logFolder.mkdirs(); 
        }

        String logFilePath = logFolderPath + File.separator + "alerts.log";
        AlertLogger logger = new AlertLogger(logFilePath);

        logger.logAlert("=== New detection session started ===");

        PacketCapture capture = new PacketCapture(csvFile);
        ThreatDetector detector = new ThreatDetector(serverUrl);

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

        System.out.println("Detection complete. Alerts logged to " + logFilePath);
    }
}
