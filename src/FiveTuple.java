package dpi;

import java.util.Objects;

public class FiveTuple {

    public final int  srcIp;    
    public final int  dstIp;
    public final int  srcPort;  
    public final int  dstPort;
    public final int  protocol; 

    public FiveTuple(int srcIp, int dstIp, int srcPort, int dstPort, int protocol) {
        this.srcIp    = srcIp;
        this.dstIp    = dstIp;
        this.srcPort  = srcPort;
        this.dstPort  = dstPort;
        this.protocol = protocol;
    }

    public FiveTuple reverse() {
        return new FiveTuple(dstIp, srcIp, dstPort, srcPort, protocol);
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof FiveTuple)) return false;
        FiveTuple t = (FiveTuple) o;
        return srcIp == t.srcIp &&
               dstIp == t.dstIp &&
               srcPort == t.srcPort &&
               dstPort == t.dstPort &&
               protocol == t.protocol;
    }

    @Override
    public int hashCode() {
        // Mirrors the hash logic from FiveTupleHash in types.h
        int h = 0;
        h ^= Integer.hashCode(srcIp)    + 0x9e3779b9 + (h << 6) + (h >>> 2);
        h ^= Integer.hashCode(dstIp)    + 0x9e3779b9 + (h << 6) + (h >>> 2);
        h ^= Integer.hashCode(srcPort)  + 0x9e3779b9 + (h << 6) + (h >>> 2);
        h ^= Integer.hashCode(dstPort)  + 0x9e3779b9 + (h << 6) + (h >>> 2);
        h ^= Integer.hashCode(protocol) + 0x9e3779b9 + (h << 6) + (h >>> 2);
        return h;
    }

    public static String ipToString(int ip) {
        return ((ip)       & 0xFF) + "." +
               ((ip >> 8)  & 0xFF) + "." +
               ((ip >> 16) & 0xFF) + "." +
               ((ip >> 24) & 0xFF);
    }

    
    public static int parseIp(String ip) {
        String[] parts = ip.split("\\.");
        int result = 0;
        int shift  = 0;
        for (String part : parts) {
            result |= (Integer.parseInt(part.trim()) & 0xFF) << shift;
            shift  += 8;
        }
        return result;
    }

    @Override
    public String toString() {
        String proto = (protocol == 6) ? "TCP" : (protocol == 17) ? "UDP" : "?";
        return ipToString(srcIp) + ":" + srcPort +
               " -> " +
               ipToString(dstIp) + ":" + dstPort +
               " (" + proto + ")";
    }
}
