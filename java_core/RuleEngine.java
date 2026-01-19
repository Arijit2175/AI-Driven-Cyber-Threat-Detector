import java.util.*;

public class RuleEngine {

    public enum Severity {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    public static class RuleResult {
        public final boolean isSuspicious;
        public final List<String> reasons;
        public final Severity severity;

        public RuleResult(boolean isSuspicious, List<String> reasons, Severity severity) {
            this.isSuspicious = isSuspicious;
            this.reasons = reasons;
            this.severity = severity;
        }
    }

    public RuleResult evaluate(double[] f) {
        List<String> reasons = new ArrayList<>();
        Severity maxSeverity = Severity.LOW;

        double duration = f[0];
        double totalPkts = f[1];
        double totalBytes = f[2];
        double meanPktLen = f[3];
        double pktRate = f[4];
        double protocol = f[5];

        if (pktRate > 100) {
            reasons.add("CRITICAL: Extreme packet rate (likely DDoS)");
            maxSeverity = updateSeverity(maxSeverity, Severity.CRITICAL);
        } else if (pktRate > 80 && duration > 5) {
            reasons.add("HIGH: Sustained high packet rate (possible DoS)");
            maxSeverity = updateSeverity(maxSeverity, Severity.HIGH);
        } else if (pktRate > 70 && duration > 2) {
            reasons.add("MEDIUM: Elevated packet rate (suspicious)");
            maxSeverity = updateSeverity(maxSeverity, Severity.MEDIUM);
        }

        if (totalBytes > 50_000_000 && meanPktLen > 1400) {
            reasons.add("HIGH: Massive data transfer with large packets (exfiltration)");
            maxSeverity = updateSeverity(maxSeverity, Severity.HIGH);
        } else if (totalBytes > 10_000_000 && duration < 10) {
            reasons.add("MEDIUM: Large rapid transfer (suspicious)");
            maxSeverity = updateSeverity(maxSeverity, Severity.MEDIUM);
        }

        if (totalPkts > 1000 && duration <= 10) {
            reasons.add("HIGH: Large packet burst (scan/flood)");
            maxSeverity = updateSeverity(maxSeverity, Severity.HIGH);
        } else if (totalPkts > 500 && duration <= 10) {
            reasons.add("MEDIUM: Rapid packet burst (scan)");
            maxSeverity = updateSeverity(maxSeverity, Severity.MEDIUM);
        }

        if (protocol == 1) { // ICMP
            if (pktRate > 30) {
                reasons.add("HIGH: ICMP flood detected");
                maxSeverity = updateSeverity(maxSeverity, Severity.HIGH);
            } else if (pktRate > 10) {
                reasons.add("MEDIUM: Elevated ICMP traffic");
                maxSeverity = updateSeverity(maxSeverity, Severity.MEDIUM);
            }
        } else if (protocol == 6) { // TCP
            if (meanPktLen < 60 && pktRate > 100) {
                reasons.add("CRITICAL: SYN flood attack pattern");
                maxSeverity = updateSeverity(maxSeverity, Severity.CRITICAL);
            } else if (meanPktLen < 60 && pktRate > 70) {
                reasons.add("HIGH: Possible SYN flood");
                maxSeverity = updateSeverity(maxSeverity, Severity.HIGH);
            }
        } else if (protocol == 17) { // UDP
            if (pktRate > 30 && meanPktLen < 100) {
                reasons.add("HIGH: UDP amplification pattern");
                maxSeverity = updateSeverity(maxSeverity, Severity.HIGH);
            }
        }

        return new RuleResult(!reasons.isEmpty(), reasons, maxSeverity);
    }

    private Severity updateSeverity(Severity current, Severity candidate) {
        return candidate.ordinal() > current.ordinal() ? candidate : current;
    }
}
