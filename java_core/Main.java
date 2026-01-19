import java.io.*;
import java.net.*;
import java.util.*;
import com.google.gson.*;

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
            System.out.println("🔴 LIVE MODE: Capturing from interface: " + cfg.interface_name);
            if (cfg.interface_name == null || cfg.interface_name.isEmpty()) {
                System.err.println("❌ No interface specified in config.json");
                PacketCapture.listInterfaces();
                return;
            }
            PacketCapture capture = new PacketCapture(cfg.interface_name, cfg.windowSeconds);

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
                } else {
                    processFlows(flows, detector, ruleEngine, logger, maliciousCsv, cfg.mlThreshold);
                }

                try {
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }

        } else {
            System.out.println("📁 CSV MODE: Processing sample_traffic.csv");
            String csvFile = "../datasets/sample_traffic.csv";
            PacketCapture capture = new PacketCapture(csvFile);
            List<Map<String, String>> flows = capture.readFlows();
            processFlows(flows, detector, ruleEngine, logger, maliciousCsv, cfg.mlThreshold);
        }
    }

    private static void processFlows(List<Map<String, String>> flows, ThreatDetector detector,
            RuleEngine ruleEngine, AlertLogger logger, File maliciousCsv,
            double mlThreshold) throws Exception {
        List<double[]> featureList = new ArrayList<>(flows.size());
        for (Map<String, String> flowMap : flows) {
            featureList.add(FeatureExtractor.extractFeatures(flowMap));
        }

        List<ThreatDetector.PredictionResult> preds = detector.predictBatch(featureList);

        int alertCount = 0;
        List<Map<String, Object>> resultPayload = new ArrayList<>();
        for (int i = 0; i < featureList.size(); i++) {
            double[] features = featureList.get(i);
            ThreatDetector.PredictionResult result = preds.get(i);
            RuleEngine.RuleResult ruleResult = ruleEngine.evaluate(features);

            boolean mlDetected = result.score >= mlThreshold;
            boolean highRule = ruleResult.severity == RuleEngine.Severity.HIGH
                    || ruleResult.severity == RuleEngine.Severity.CRITICAL;
            boolean detected = mlDetected || highRule;

            if (i < 3) {
                System.out.println("  [DEBUG] Flow " + i + ": pred=" + result.prediction +
                        ", score=" + String.format("%.4f", result.score) +
                        ", threshold=" + String.format("%.4f", mlThreshold) +
                        ", features=" + Arrays.toString(features));
            }

            if (detected) {
                alertCount++;
                String confidence = String.format("%.2f%%", result.score * 100);
                String severityIcon = getSeverityIcon(ruleResult.severity);

                String reason;
                if (mlDetected && ruleResult.isSuspicious) {
                    reason = "ML+Rules [" + ruleResult.severity + "] (ML: " + confidence + ", "
                            + String.join("; ", ruleResult.reasons) + ")";
                } else if (mlDetected) {
                    reason = "ML (confidence: " + confidence + ")";
                } else {
                    reason = "Rules [" + ruleResult.severity + "]: " + String.join("; ", ruleResult.reasons);
                }

                logger.logAlert("Detected malicious/suspicious flow (" + reason + "): " + Arrays.toString(features));
                System.out.println(severityIcon + " ALERT! " + reason);
                System.out.println("   Features: " + Arrays.toString(features));
                try (PrintWriter pw = new PrintWriter(new FileWriter(maliciousCsv, true))) {
                    pw.println(features[0] + "," + features[1] + "," + features[2] + "," +
                            features[3] + "," + features[4] + "," + features[5]);
                }
            }

            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("duration", features[0]);
            entry.put("total_pkts", features[1]);
            entry.put("total_bytes", features[2]);
            entry.put("mean_pkt_len", features[3]);
            entry.put("pkt_rate", features[4]);
            entry.put("protocol", features[5]);
            entry.put("prediction", result.prediction);
            entry.put("score", result.score);
            entry.put("severity", ruleResult.severity.toString());
            entry.put("is_alert", detected);
            resultPayload.add(entry);
        }

        System.out.println("  Processed " + flows.size() + " flows → " + alertCount + " alerts");

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

            conn.getResponseCode();
        } catch (Exception e) {

        }
    }

    private static String getSeverityIcon(RuleEngine.Severity severity) {
        switch (severity) {
            case CRITICAL:
                return "🔴";
            case HIGH:
                return "🟠";
            case MEDIUM:
                return "🟡";
            case LOW:
                return "🟢";
            default:
                return "🚨";
        }
    }
}
