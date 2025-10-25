import com.google.gson.*;
import java.io.*;
import java.net.*;
import java.util.*;

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
        conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
        conn.setDoOutput(true);

        Map<String, Object> payload = new HashMap<>();
        payload.put("features", features);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(gson.toJson(payload).getBytes("utf-8"));
        }

        try (InputStreamReader reader = new InputStreamReader(conn.getInputStream(), "utf-8")) {
            JsonObject response = gson.fromJson(reader, JsonObject.class);
            if (response.has("prediction")) return response.get("prediction").getAsInt();
            else throw new IOException("No 'prediction' in response: " + response);
        }
    }

    public List<Integer> predictBatch(List<double[]> flows) throws IOException {
        URL url = new URL(serverUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
        conn.setDoOutput(true);

        List<Map<String, Object>> jsonFlows = new ArrayList<>();
        for (double[] f : flows) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("duration", f[0]);
            m.put("total_pkts", f[1]);
            m.put("total_bytes", f[2]);
            m.put("mean_pkt_len", f[3]);
            m.put("pkt_rate", f[4]);
            m.put("protocol", f[5]);
            jsonFlows.add(m);
        }

        Map<String, Object> payload = new HashMap<>();
        payload.put("flows", jsonFlows);

        try (OutputStream os = conn.getOutputStream()) {
            os.write(gson.toJson(payload).getBytes("utf-8"));
        }

        try (InputStreamReader reader = new InputStreamReader(conn.getInputStream(), "utf-8")) {
            JsonObject response = gson.fromJson(reader, JsonObject.class);
            if (!response.has("predictions")) throw new IOException("No 'predictions' in response: " + response);

            List<Integer> out = new ArrayList<>();
            for (JsonElement e : response.getAsJsonArray("predictions")) out.add(e.getAsInt());
            return out;
        }
    }
}
