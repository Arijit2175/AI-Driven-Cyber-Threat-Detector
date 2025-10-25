import java.io.*;
import java.time.LocalDateTime;
import java.util.Arrays;

public class AlertLogger {

    private String logFile;
    private String maliciousCsvFile;
    private boolean writeMaliciousCsv;

    public AlertLogger(String logFile) {
        this.logFile = logFile;
        this.writeMaliciousCsv = false;
    }

    public AlertLogger(String logFile, String maliciousCsvFile) {
        this.logFile = logFile;
        this.maliciousCsvFile = maliciousCsvFile;
        this.writeMaliciousCsv = true;

        File csvFile = new File(maliciousCsvFile);
        File parentDir = csvFile.getParentFile();
        if (!parentDir.exists()) {
            parentDir.mkdirs();
        }

        if (!csvFile.exists()) {
            try (PrintWriter pw = new PrintWriter(new FileWriter(csvFile, true))) {
                pw.println("duration,total_pkts,total_bytes,mean_pkt_len,pkt_rate,protocol");
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void logAlert(String message) {
        try (FileWriter fw = new FileWriter(logFile, true);
             BufferedWriter bw = new BufferedWriter(fw);
             PrintWriter out = new PrintWriter(bw)) {
            out.println(LocalDateTime.now() + " - ALERT: " + message);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void logMaliciousFlow(double[] features) {
        if (!writeMaliciousCsv) return;

        try (PrintWriter pw = new PrintWriter(new FileWriter(maliciousCsvFile, true))) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < features.length; i++) {
                sb.append(features[i]);
                if (i < features.length - 1) sb.append(",");
            }
            pw.println(sb.toString());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void logMalicious(double[] features) {
        logAlert("Malicious flow detected: " + Arrays.toString(features));
        logMaliciousFlow(features);
    }
}
