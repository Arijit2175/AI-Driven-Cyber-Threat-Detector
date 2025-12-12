import java.io.*;
import java.net.*;
import java.util.*;
import com.google.gson.*;

// The main class to run the AI-driven cyber threat detection system.
public class Main {

    public static void main(String[] args) throws Exception {

        File projectRoot = new File("..");
        Config cfg = Config.load(projectRoot.getAbsolutePath());

        String serverUrl = cfg.serverUrl;
        boolean liveMode = args.length > 0 && args[0].equals("--live");

        File logsFolder = new File("../logs");
        if (!logsFolder.exists())
            logsFolder.mkdirs();

        File logFile = new File(logsFolder, "alerts.log");
        AlertLogger logger = new AlertLogger(logFile.getAbsolutePath());
        logger.logAlert("=== New detection session started ===");

        File maliciousCsv = new File(logsFolder, "malicious_flows.csv");
        if (!maliciousCsv.exists()) {
            try (PrintWriter pw = new PrintWriter(new FileWriter(maliciousCsv, true))) {
                pw.println("duration,total_pkts,total_bytes,mean_pkt_len,pkt_rate,protocol");
            }
        }

        ThreatDetector detector = new ThreatDetector(serverUrl);
        RuleEngine ruleEngine = new RuleEngine();

        if (liveMode) {
            System.out.println("🔴 LIVE MODE: Capturing from interface: " + cfg.interfaceName);
            PacketCapture capture = new PacketCapture(cfg.interfaceName, cfg.windowSeconds);

            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                capture.close();
                System.out.println("\nCapture stopped.");
            }));

            int windowCount = 0;
            while (true) {
                windowCount++;
                System.out.println("\n📊 Window #" + windowCount + " (" + cfg.windowSeconds + "s)");

                List<Map<String, String>> flows = capture.captureNextWindow();
                if (flows.isEmpty()) {
                    System.out.println("  No flows captured in this window.");
                    continue;
                }

                processFlows(flows, detector, ruleEngine, logger, maliciousCsv);
            }

        } else {
            System.out.println("📁 CSV MODE: Processing sample_traffic.csv");
            String csvFile = "../datasets/sample_traffic.csv";
            PacketCapture capture = new PacketCapture(csvFile);
            List<Map<String, String>> flows = capture.readFlows();
            processFlows(flows, detector, ruleEngine, logger, maliciousCsv);
        }
    }

    private static void processFlows(List<Map<String, String>> flows, ThreatDetector detector,
            RuleEngine ruleEngine, AlertLogger logger, File maliciousCsv) throws Exception {
        List<double[]> featureList = new ArrayList<>(flows.size());
        for (Map<String, String> flowMap : flows) {
            featureList.add(FeatureExtractor.extractFeatures(flowMap));
        }

        List<Integer> preds = detector.predictBatch(featureList);

        int alertCount = 0;
        for (int i = 0; i < featureList.size(); i++) {
            double[] features = featureList.get(i);
            int prediction = preds.get(i);
            RuleEngine.RuleResult ruleResult = ruleEngine.evaluate(features);

            boolean detected = prediction == 1 || ruleResult.isSuspicious;

            if (detected) {
                alertCount++;
                String reason = prediction == 1 ? "ML classified malicious" : String.join("; ", ruleResult.reasons);
                logger.logAlert("Detected malicious/suspicious flow (" + reason + "): " + Arrays.toString(features));
                System.out.println("🚨 ALERT! " + reason);
                System.out.println("   Features: " + Arrays.toString(features));
                try (PrintWriter pw = new PrintWriter(new FileWriter(maliciousCsv, true))) {
                    pw.println(features[0] + "," + features[1] + "," + features[2] + "," +
                            features[3] + "," + features[4] + "," + features[5]);
                }
            }
        }

        System.out.println("  Processed " + flows.size() + " flows → " + alertCount + " alerts");
    }
}
