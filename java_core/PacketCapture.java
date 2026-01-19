import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;

public class PacketCapture {
    private String csvPath;
    private PcapHandle handle;
    private int windowSeconds;

    private Map<String, FlowStats> activeFlows = new ConcurrentHashMap<>();
    private long windowStartTime;

    public PacketCapture(String csvPath) {
        this.csvPath = csvPath;
    }

    public PacketCapture(String interfaceName, int windowSeconds) throws PcapNativeException {
        this.windowSeconds = windowSeconds;
        PcapNetworkInterface nif = findInterface(interfaceName);
        if (nif == null) {
            System.err.println("Interface not found: " + interfaceName);
            listInterfaces();
            throw new PcapNativeException("Interface not found: " + interfaceName);
        }

        this.handle = nif.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
        this.windowStartTime = System.currentTimeMillis();
        System.out.println("✓ Capturing on interface: " + nif.getName());
    }

    public static void listInterfaces() throws PcapNativeException {
        System.out.println("Available network interfaces:");
        for (PcapNetworkInterface nif : Pcaps.findAllDevs()) {
            System.out.println("  - " + nif.getName() + " (" + nif.getDescription() + ")");
        }
    }

    public static void main(String[] args) throws Exception {
        listInterfaces();
    }

    private static PcapNetworkInterface findInterface(String name) throws PcapNativeException {
        List<PcapNetworkInterface> nifs = Pcaps.findAllDevs();

        if (name != null && name.equalsIgnoreCase("LOOPBACK")) {
            for (PcapNetworkInterface nif : nifs) {
                String desc = nif.getDescription();
                String n = nif.getName();
                if ((desc != null && desc.toLowerCase().contains("loopback")) ||
                        (n != null && n.toLowerCase().contains("loopback"))) {
                    return nif;
                }
            }
        }

        for (PcapNetworkInterface nif : nifs) {
            if (nif.getName().equalsIgnoreCase(name) ||
                    (nif.getDescription() != null && nif.getDescription().contains(name))) {
                return nif;
            }
        }
        return null;
    }

    public List<Map<String, String>> readFlows() throws IOException {
        List<Map<String, String>> flows = new ArrayList<>();
        List<String> lines = Files.readAllLines(Paths.get(csvPath));
        boolean first = true;
        for (String line : lines) {
            if (first) {
                first = false;
                continue;
            }
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

    public List<Map<String, String>> captureNextWindow()
            throws PcapNativeException, NotOpenException, InterruptedException {
        long now = System.currentTimeMillis();
        long elapsed = now - windowStartTime;

        while (elapsed < windowSeconds * 1000) {
            try {
                Packet packet = handle.getNextPacketEx();
                if (packet != null) {
                    processPacket(packet);
                }
            } catch (EOFException | TimeoutException e) {
                
            }
            elapsed = System.currentTimeMillis() - windowStartTime;
        }

        List<Map<String, String>> flows = aggregateFlows();
        activeFlows.clear();
        windowStartTime = System.currentTimeMillis();

        return flows;
    }

    private void processPacket(Packet packet) {
        try {
            IpPacket ipPacket = packet.get(IpPacket.class);
            if (ipPacket == null)
                return;

            String srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
            String dstIp = ipPacket.getHeader().getDstAddr().getHostAddress();
            int protocol = ipPacket.getHeader().getProtocol().value() & 0xFF;
            int length = ipPacket.length();

            String flowKey = srcIp + "-" + dstIp + "-" + protocol;

            FlowStats stats = activeFlows.computeIfAbsent(flowKey, k -> new FlowStats(protocol));
            stats.addPacket(length);

        } catch (Exception e) {
            
        }
    }

    private List<Map<String, String>> aggregateFlows() {
        List<Map<String, String>> flows = new ArrayList<>();
        double duration = windowSeconds;

        for (FlowStats stats : activeFlows.values()) {
            Map<String, String> flow = new HashMap<>();
            flow.put("duration", String.valueOf(duration));
            flow.put("total_pkts", String.valueOf(stats.packetCount));
            flow.put("total_bytes", String.valueOf(stats.totalBytes));
            flow.put("mean_pkt_len", String.valueOf(stats.getMeanPacketLength()));
            flow.put("pkt_rate", String.valueOf(stats.getPacketRate(duration)));
            flow.put("protocol", String.valueOf(stats.protocol));
            flows.add(flow);
        }

        return flows;
    }

    public void close() {
        if (handle != null && handle.isOpen()) {
            handle.close();
        }
    }

    private static class FlowStats {
        int protocol;
        int packetCount;
        long totalBytes;

        FlowStats(int protocol) {
            this.protocol = protocol;
        }

        void addPacket(int length) {
            packetCount++;
            totalBytes += length;
        }

        double getMeanPacketLength() {
            return packetCount > 0 ? (double) totalBytes / packetCount : 0;
        }

        double getPacketRate(double duration) {
            return duration > 0 ? packetCount / duration : 0;
        }
    }
}