package dpi;

import java.io.IOException;
import java.util.*;

public class DpiEngine {
    public static void main(String[] args) {
        if (args.length < 2) {
            printUsage();
            System.exit(1);
        }

        String       inputFile  = args[0];
        String       outputFile = args[1];
        BlockingRules rules     = new BlockingRules();

        // Parse command-line options (mirrors the C++ option parsing)
        for (int i = 2; i < args.length; i++) {
            switch (args[i]) {
                case "--block-ip":
                    if (i + 1 < args.length) rules.blockIp(args[++i]);
                    break;
                case "--block-app":
                    if (i + 1 < args.length) rules.blockApp(args[++i]);
                    break;
                case "--block-domain":
                    if (i + 1 < args.length) rules.blockDomain(args[++i]);
                    break;
                default:
                    System.err.println("Unknown option: " + args[i]);
            }
        }

        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                    DPI ENGINE v1.0 (Java)                    ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
        System.out.println();

        try {
            run(inputFile, outputFile, rules);
        } catch (IOException e) {
            System.err.println("Fatal error: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void run(String inputFile, String outputFile, BlockingRules rules)
            throws IOException {

        PcapReader reader = new PcapReader();
        if (!reader.open(inputFile)) {
            System.err.println("Error: Cannot open input file: " + inputFile);
            System.exit(1);
        }

        PcapWriter writer = new PcapWriter();
        writer.open(outputFile);

        // Flow table: FiveTuple → Flow  (mirrors std::unordered_map<FiveTuple, Flow>)
        Map<FiveTuple, Flow> flows = new HashMap<>();

        // Statistics
        long totalPackets = 0;
        long forwarded    = 0;
        long dropped      = 0;
        Map<AppType, Long> appStats = new LinkedHashMap<>();

        System.out.println("[DPI] Processing packets...");

        RawPacket    raw;
        ParsedPacket parsed = new ParsedPacket();

        while ((raw = reader.readNextPacket()) != null) {
            totalPackets++;

            if (!PacketParser.parse(raw, parsed)) continue;
            if (!parsed.hasIp) continue;
            if (!parsed.hasTcp && !parsed.hasUdp) continue;

            // Build FiveTuple from the parsed packet
            FiveTuple tuple = new FiveTuple(
                PacketParser.parseIpString(parsed.srcIp),
                PacketParser.parseIpString(parsed.destIp),
                parsed.srcPort,
                parsed.destPort,
                parsed.protocol
            );

            // Get or create the flow for this 5-tuple
            Flow flow = flows.computeIfAbsent(tuple, Flow::new);
            flow.packets++;
            flow.bytes += raw.data.length;

            if ((flow.appType == AppType.UNKNOWN || flow.appType == AppType.HTTPS)
                    && flow.sni.isEmpty()
                    && parsed.hasTcp
                    && parsed.destPort == 443
                    && parsed.payloadLength > 5) {

                String sni = SniExtractor.extract(
                        raw.data, parsed.payloadOffset, parsed.payloadLength);

                if (sni != null && !sni.isEmpty()) {
                    flow.sni     = sni;
                    flow.appType = AppType.fromSni(sni);
                }
            }

            if ((flow.appType == AppType.UNKNOWN || flow.appType == AppType.HTTP)
                    && flow.sni.isEmpty()
                    && parsed.hasTcp
                    && parsed.destPort == 80
                    && parsed.payloadLength > 4) {

                String host = SniExtractor.extractHttpHost(
                        raw.data, parsed.payloadOffset, parsed.payloadLength);

                if (host != null && !host.isEmpty()) {
                    flow.sni     = host;
                    flow.appType = AppType.fromSni(host);
                }
            }

            if (flow.appType == AppType.UNKNOWN
                    && (parsed.destPort == 53 || parsed.srcPort == 53)) {
                flow.appType = AppType.DNS;
            }

            if (flow.appType == AppType.UNKNOWN) {
                if      (parsed.destPort == 443) flow.appType = AppType.HTTPS;
                else if (parsed.destPort == 80)  flow.appType = AppType.HTTP;
            }

            if (!flow.blocked) {
                flow.blocked = rules.isBlocked(tuple.srcIp, flow.appType, flow.sni);
                if (flow.blocked) {
                    System.out.print("[BLOCKED] " + parsed.srcIp +
                                     " -> " + parsed.destIp +
                                     " (" + flow.appType.toDisplayString());
                    if (!flow.sni.isEmpty()) System.out.print(": " + flow.sni);
                    System.out.println(")");
                }
            }

            // Update per-app statistics
            appStats.merge(flow.appType, 1L, Long::sum);

            if (flow.blocked) {
                dropped++;
            } else {
                forwarded++;
                writer.writePacket(raw);
            }
        }

        reader.close();
        writer.close();
        
        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                      PROCESSING REPORT                       ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.printf( "║ Total Packets:      %10d                             ║%n", totalPackets);
        System.out.printf( "║ Forwarded:          %10d                             ║%n", forwarded);
        System.out.printf( "║ Dropped:            %10d                             ║%n", dropped);
        System.out.printf( "║ Active Flows:       %10d                             ║%n", flows.size());
        System.out.println("╠══════════════════════════════════════════════════════════════╣");
        System.out.println("║                    APPLICATION BREAKDOWN                     ║");
        System.out.println("╠══════════════════════════════════════════════════════════════╣");

        // Sort app stats by count descending
        List<Map.Entry<AppType, Long>> sorted = new ArrayList<>(appStats.entrySet());
        sorted.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

        for (Map.Entry<AppType, Long> entry : sorted) {
            AppType app   = entry.getKey();
            long    count = entry.getValue();
            double  pct   = 100.0 * count / totalPackets;
            int     bars  = (int) (pct / 5);
            String  bar   = "#".repeat(bars);

            System.out.printf("║ %-15s %8d %5.1f%% %-20s  ║%n",
                    app.toDisplayString(), count, pct, bar);
        }

        System.out.println("╚══════════════════════════════════════════════════════════════╝");

        // Print detected SNIs / domains
        System.out.println();
        System.out.println("[Detected Applications/Domains]");
        Map<String, AppType> uniqueSnis = new LinkedHashMap<>();
        for (Flow f : flows.values()) {
            if (!f.sni.isEmpty()) {
                uniqueSnis.put(f.sni, f.appType);
            }
        }
        for (Map.Entry<String, AppType> e : uniqueSnis.entrySet()) {
            System.out.println("  - " + e.getKey() + " -> " + e.getValue().toDisplayString());
        }

        System.out.println();
        System.out.println("Output written to: " + outputFile);
    }

    // -------------------------------------------------------------------------

    private static void printUsage() {
        System.out.println();
        System.out.println("DPI Engine - Deep Packet Inspection System (Java)");
        System.out.println("=================================================");
        System.out.println();
        System.out.println("Usage: java -cp . dpi.DpiEngine <input.pcap> <output.pcap> [options]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --block-ip <ip>        Block traffic from source IP");
        System.out.println("  --block-app <app>      Block application (YouTube, Facebook, TikTok, ...)");
        System.out.println("  --block-domain <dom>   Block domain substring match");
        System.out.println();
        System.out.println("Example:");
        System.out.println("  java -cp . dpi.DpiEngine capture.pcap filtered.pcap --block-app YouTube");
    }
}
