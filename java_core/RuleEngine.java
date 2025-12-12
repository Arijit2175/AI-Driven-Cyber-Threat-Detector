import java.util.*;

// Simple heuristic-based detection rules to complement ML predictions.
public class RuleEngine {

    public static class RuleResult {
        public final boolean isSuspicious;
        public final List<String> reasons;

        public RuleResult(boolean isSuspicious, List<String> reasons) {
            this.isSuspicious = isSuspicious;
            this.reasons = reasons;
        }
    }

    // Evaluate static rules over feature vector: [duration, total_pkts,
    // total_bytes, mean_pkt_len, pkt_rate, protocol]
    public RuleResult evaluate(double[] f) {
        List<String> reasons = new ArrayList<>();

        double duration = f[0];
        double totalPkts = f[1];
        double totalBytes = f[2];
        double meanPktLen = f[3];
        double pktRate = f[4];
        double protocol = f[5];

        // Example rules (tune thresholds for your data):
        if (pktRate > 10000 && duration > 5) {
            reasons.add("High packet rate sustained over time (possible DoS)");
        }
        if (totalBytes > 5_000_000 && meanPktLen > 1400) {
            reasons.add("Large transfer with jumbo packets (possible data exfiltration)");
        }
        if (totalPkts > 50_000 && duration < 2) {
            reasons.add("Packet burst in short duration (scan or flood)");
        }
        if (protocol == 0 && pktRate > 2000) {
            reasons.add("Unusual high-rate ICMP traffic");
        }
        if (meanPktLen < 60 && pktRate > 3000) {
            reasons.add("Tiny packets at high rate (possible SYN flood)");
        }

        return new RuleResult(!reasons.isEmpty(), reasons);
    }
}
