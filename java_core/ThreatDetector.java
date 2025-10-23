import java.io.*;
import java.net.*;
import java.util.*;
import com.google.gson.*;

public class ThreatDetector {

    private String serverUrl;
    private Gson gson = new Gson();

    public ThreatDetector(String serverUrl) {
        this.serverUrl = serverUrl;
    }

    public int predict(double[] features) throws IOException {
        URL url = new URL(serverUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);

        Map<String, Object> payload = new HashMap<>();
        payload.put("features", features);

        try (OutputStream os = conn.getOutputStream()) {
            byte[] input = gson.toJson(payload).getBytes("utf-8");
            os.write(input, 0, input.length);
        }

        InputStreamReader reader = new InputStreamReader(conn.getInputStream(), "utf-8");
        JsonObject response = gson.fromJson(reader, JsonObject.class);
        return response.get("prediction").getAsInt();
    }
}