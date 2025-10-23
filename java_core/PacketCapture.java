import java.io.*;
import java.nio.file.*;
import java.util.*;

public class PacketCapture {
    private String csvPath;

    public PacketCapture(String csvPath) {
        this.csvPath = csvPath;
    }

    public List<Map<String, String>> readFlows() throws IOException {
        List<Map<String, String>> flows = new ArrayList<>();
        List<String> lines = Files.readAllLines(Paths.get(csvPath));
        boolean first = true;
        for (String line : lines) {
            if (first) { first = false; continue; } 
            String[] parts = line.split(",");
            Map<String, String> flow = new HashMap<>();
            flow.put("duration", parts[1]);
            flow.put("total_pkts", parts[2]);
            flow.put("total_bytes", parts[3]);
            flow.put("mean_pkt_len", parts[4]);
            flow.put("pkt_rate", parts[5]);
            flow.put("protocol", parts[6]);
            flows.add(flow);
        }
        return flows;
    }
}