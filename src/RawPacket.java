package dpi;

public class RawPacket {

    public final long   tsSec;    // Timestamp seconds   (uint32_t in C++)
    public final long   tsUsec;   // Timestamp microseconds
    public final long   inclLen;  // Bytes captured in file
    public final long   origLen;  // Original packet length on the wire
    public final byte[] data;     // Raw packet bytes

    public RawPacket(long tsSec, long tsUsec, long inclLen, long origLen, byte[] data) {
        this.tsSec   = tsSec;
        this.tsUsec  = tsUsec;
        this.inclLen = inclLen;
        this.origLen = origLen;
        this.data    = data;
    }
}
