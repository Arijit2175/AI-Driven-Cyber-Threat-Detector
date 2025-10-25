import java.io.*;
import java.util.*;

public class Main {

    public static void main(String[] args) throws Exception {
        String datasetFolder = "../datasets"; 
        String serverUrl = "http://127.0.0.1:5000/predict";
        String outputCsv = "../datasets/malicious_flows.csv";

        File outFile = new File(outputCsv);
        try (PrintWriter writer = new PrintWriter(new FileWriter(outFile))) {
            writer.println("duration,total_pkts,total_bytes,mean_pkt_len,pkt_rate,protocol"); // CSV header
        }

        File folder = new File(datasetFolder);
        File[] csvFiles = folder.listFiles((dir, name) -> name.toLowerCase().endsWith(".csv"));

        if (csvFiles == null || csvFiles.length == 0) {
            System.out.println("No CSV files found in " + datasetFolder);
            return;
        }

        PacketCapture capture;
        ThreatDetector detector = new ThreatDetector(serverUrl);

        for (File csvFile : csvFiles) {
            System.out.println("Processing file: " + csvFile.getName());
            capture = new PacketCapture(csvFile.getAbsolutePath());
            List<Map<String, String>> flows = capture.readFlows();

            for (Map<String, String> flowMap : flows) {
                double[] features = FeatureExtractor.extractFeatures(flowMap);
                int prediction = detector.predict(features);

                if (prediction == 1) {
                    System.out.println("ALERT! Malicious flow: " + Arrays.toString(features));
                    try (PrintWriter writer = new PrintWriter(new FileWriter(outFile, true))) {
                        writer.println(String.join(",", Arrays.stream(features)
                                .mapToObj(Double::toString)
                                .toArray(String[]::new)));
                    }
                } else {
                    System.out.println("Normal flow: " + Arrays.toString(features));
                }
            }
        }

        System.out.println("Batch detection complete. Malicious flows saved to " + outputCsv);
    }
}
