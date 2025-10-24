import java.util.*;

public class FeatureExtractor {

    public static double[] extractFeatures(Map<String, String> flow) {
        double duration = Double.parseDouble(flow.get("duration"));
        double total_pkts = Double.parseDouble(flow.get("total_pkts"));
        double total_bytes = Double.parseDouble(flow.get("total_bytes"));
        double mean_pkt_len = Double.parseDouble(flow.get("mean_pkt_len"));
        double pkt_rate = Double.parseDouble(flow.get("pkt_rate"));
        String proto = flow.get("protocol").toUpperCase();
        int protocol;
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
        return new double[]{duration, total_pkts, total_bytes, mean_pkt_len, pkt_rate, protocol};
    }
}

