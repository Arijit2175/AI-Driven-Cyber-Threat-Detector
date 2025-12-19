import java.util.*;

// A utility class to extract features from network flow data represented as a map.
public class FeatureExtractor {

    public static double[] extractFeatures(Map<String, String> flow) {
        double duration = Double.parseDouble(flow.get("duration"));
        double total_pkts = Double.parseDouble(flow.get("total_pkts"));
        double total_bytes = Double.parseDouble(flow.get("total_bytes"));
        double mean_pkt_len = Double.parseDouble(flow.get("mean_pkt_len"));
        double pkt_rate = Double.parseDouble(flow.get("pkt_rate"));
        String protoRaw = flow.get("protocol");
        int protocol;
        if (protoRaw != null && protoRaw.matches("\\d+")) {
            // Protocol provided as numeric code (e.g., 6, 17, 1)
            protocol = Integer.parseInt(protoRaw);
        } else {
            String proto = protoRaw == null ? "" : protoRaw.toUpperCase();
            switch (proto) {
                case "TCP":
                    protocol = 6;
                    break;
                case "UDP":
                    protocol = 17;
                    break;
                case "ICMP":
                    protocol = 1;
                    break;
                default:
                    protocol = 0;
            }
        }
        return new double[] { duration, total_pkts, total_bytes, mean_pkt_len, pkt_rate, protocol };
    }
}
