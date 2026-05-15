package dpi;

public class ParsedPacket {

    // --- Ethernet ---
    public String srcMac  = "";
    public String dstMac  = "";
    public int    etherType = 0;   // 0x0800 = IPv4

    // --- IPv4 ---
    public boolean hasIp      = false;
    public int     ipVersion  = 0;
    public String  srcIp      = "";
    public String  destIp     = "";
    public int     ttl        = 0;
    public int     protocol   = 0; // 6=TCP, 17=UDP

    // --- TCP ---
    public boolean hasTcp     = false;
    public int     srcPort    = 0;
    public int     destPort   = 0;
    public long    seqNumber  = 0;
    public long    ackNumber  = 0;
    public int     tcpFlags   = 0;

    // --- UDP ---
    public boolean hasUdp     = false;
    // srcPort / destPort shared with TCP fields above

    // --- Payload ---
    public int    payloadOffset = 0;  // byte offset within raw data[]
    public int    payloadLength = 0;

    // Timestamp (copied from RawPacket)
    public long tsSec  = 0;
    public long tsUsec = 0;
}
