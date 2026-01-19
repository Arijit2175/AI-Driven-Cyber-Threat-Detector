import com.google.gson.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

public class Config {
    public String interface_name;
    public int windowSeconds;
    public int batchSize;
    public String serverUrl;
    public double mlThreshold;

    public static class Rules {
        public int icmpRate;
        public int synRate;
        public int burstPkts;
    }

    public Rules rules;

    public static Config load(String projectRoot) throws IOException {
        File cfg = new File(projectRoot, "config.json");
        try (InputStream is = new FileInputStream(cfg)) {
            String json = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            return new Gson().fromJson(json, Config.class);
        }
    }
}
