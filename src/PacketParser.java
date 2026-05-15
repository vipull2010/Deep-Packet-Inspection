package dpi;


public class PacketParser {

    // EtherType constants
    private static final int ETHERTYPE_IPV4 = 0x0800;

    // IP protocol constants
    public static final int PROTO_ICMP = 1;
    public static final int PROTO_TCP  = 6;
    public static final int PROTO_UDP  = 17;

    // TCP flag bitmasks
    public static final int TCP_FIN = 0x01;
    public static final int TCP_SYN = 0x02;
    public static final int TCP_RST = 0x04;
    public static final int TCP_PSH = 0x08;
    public static final int TCP_ACK = 0x10;
    public static final int TCP_URG = 0x20;


    public static boolean parse(RawPacket raw, ParsedPacket parsed) {
        parsed.tsSec  = raw.tsSec;
        parsed.tsUsec = raw.tsUsec;

        byte[] data = raw.data;
        int    len  = data.length;
        int    offset;

        // 1. Ethernet header
        offset = parseEthernet(data, len, parsed);
        if (offset < 0) return false;

        // 2. IPv4
        if (parsed.etherType != ETHERTYPE_IPV4) return false;

        offset = parseIPv4(data, len, offset, parsed);
        if (offset < 0) return false;

        // 3. Transport layer
        if (parsed.protocol == PROTO_TCP) {
            offset = parseTCP(data, len, offset, parsed);
            if (offset < 0) return false;
        } else if (parsed.protocol == PROTO_UDP) {
            offset = parseUDP(data, len, offset, parsed);
            if (offset < 0) return false;
        }

        // 4. Payload
        parsed.payloadOffset = offset;
        parsed.payloadLength = (offset < len) ? (len - offset) : 0;

        return true;
    }

    private static int parseEthernet(byte[] data, int len, ParsedPacket p) {
        final int ETH_LEN = 14;
        if (len < ETH_LEN) return -1;

        p.dstMac    = macToString(data, 0);
        p.srcMac    = macToString(data, 6);
        p.etherType = readUint16BE(data, 12);

        return ETH_LEN;
    }

    private static int parseIPv4(byte[] data, int len, int offset, ParsedPacket p) {
        final int MIN_IP = 20;
        if (len < offset + MIN_IP) return -1;

        int versionIhl = data[offset] & 0xFF;
        p.ipVersion    = (versionIhl >> 4) & 0x0F;
        int ihl        = (versionIhl & 0x0F) * 4; // header length in bytes

        if (p.ipVersion != 4) return -1;
        if (ihl < MIN_IP || len < offset + ihl) return -1;

        p.ttl      = data[offset + 8] & 0xFF;
        p.protocol = data[offset + 9] & 0xFF;

        // Source IP — 4 bytes at offset+12, network (big-endian) order
        p.srcIp  = ipBytesToString(data, offset + 12);
        p.destIp = ipBytesToString(data, offset + 16);

        p.hasIp = true;
        return offset + ihl;
    }

    private static int parseTCP(byte[] data, int len, int offset, ParsedPacket p) {
        final int MIN_TCP = 20;
        if (len < offset + MIN_TCP) return -1;

        p.srcPort  = readUint16BE(data, offset);
        p.destPort = readUint16BE(data, offset + 2);
        p.seqNumber = readUint32BE(data, offset + 4);
        p.ackNumber = readUint32BE(data, offset + 8);

        int dataOffset = ((data[offset + 12] & 0xFF) >> 4) * 4; // in bytes
        p.tcpFlags = data[offset + 13] & 0xFF;

        if (dataOffset < MIN_TCP || len < offset + dataOffset) return -1;

        p.hasTcp = true;
        return offset + dataOffset;
    }

    private static int parseUDP(byte[] data, int len, int offset, ParsedPacket p) {
        final int UDP_LEN = 8;
        if (len < offset + UDP_LEN) return -1;

        p.srcPort  = readUint16BE(data, offset);
        p.destPort = readUint16BE(data, offset + 2);

        p.hasUdp = true;
        return offset + UDP_LEN;
    }

    /** Read 2 bytes big-endian as unsigned int. */
    public static int readUint16BE(byte[] data, int offset) {
        return ((data[offset]     & 0xFF) << 8) |
                (data[offset + 1] & 0xFF);
    }

    /** Read 4 bytes big-endian as unsigned long. */
    public static long readUint32BE(byte[] data, int offset) {
        return ((data[offset]     & 0xFFL) << 24) |
               ((data[offset + 1] & 0xFFL) << 16) |
               ((data[offset + 2] & 0xFFL) <<  8) |
                (data[offset + 3] & 0xFFL);
    }

    /** Read 3 bytes big-endian as unsigned int. */
    public static int readUint24BE(byte[] data, int offset) {
        return ((data[offset]     & 0xFF) << 16) |
               ((data[offset + 1] & 0xFF) <<  8) |
                (data[offset + 2] & 0xFF);
    }

    private static String macToString(byte[] data, int offset) {
        StringBuilder sb = new StringBuilder(17);
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02x", data[offset + i] & 0xFF));
        }
        return sb.toString();
    }

    static String ipBytesToString(byte[] data, int offset) {
        return (data[offset]     & 0xFF) + "." +
               (data[offset + 1] & 0xFF) + "." +
               (data[offset + 2] & 0xFF) + "." +
               (data[offset + 3] & 0xFF);
    }

    public static int parseIpString(String ip) {
        return FiveTuple.parseIp(ip);
    }
    
    public static String tcpFlagsToString(int flags) {
        StringBuilder sb = new StringBuilder();
        if ((flags & TCP_SYN) != 0) sb.append("SYN ");
        if ((flags & TCP_ACK) != 0) sb.append("ACK ");
        if ((flags & TCP_FIN) != 0) sb.append("FIN ");
        if ((flags & TCP_RST) != 0) sb.append("RST ");
        if ((flags & TCP_PSH) != 0) sb.append("PSH ");
        if ((flags & TCP_URG) != 0) sb.append("URG ");
        String result = sb.toString().trim();
        return result.isEmpty() ? "none" : result;
    }
}
