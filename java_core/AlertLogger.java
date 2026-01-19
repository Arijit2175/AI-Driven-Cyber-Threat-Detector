import java.io.*;
import java.time.LocalDateTime;

public class AlertLogger {

    private String logFile;

    public AlertLogger(String logFile) {
        this.logFile = logFile;
        File parentDir = new File(logFile).getParentFile();
        if (!parentDir.exists()) {
            parentDir.mkdirs();
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
}
