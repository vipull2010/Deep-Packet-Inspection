package dpi;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;


public class PcapReader implements Closeable {

    // PCAP magic numbers
    private static final int PCAP_MAGIC_NATIVE  = 0xa1b2c3d4; // little-endian file
    private static final int PCAP_MAGIC_SWAPPED = 0xd4c3b2a1; // big-endian file

    // Global header fields (read once at open time)
    private int     versionMajor;
    private int     versionMinor;
    private long    snaplen;
    private long    network;
    private boolean needsByteSwap = false;
    private boolean isOpen        = false;

    private DataInputStream in;
    private String          filename;

    
    public boolean open(String filename) throws IOException {
        this.filename = filename;

        FileInputStream fis = new FileInputStream(filename);
        in = new DataInputStream(new BufferedInputStream(fis));

        // --- Read 24-byte global header ---
        // Byte order is determined by magic number, so read raw bytes first
        byte[] hdrBytes = new byte[24];
        int bytesRead = in.read(hdrBytes);
        if (bytesRead < 24) {
            System.err.println("Error: Could not read PCAP global header");
            in.close();
            return false;
        }

        ByteBuffer buf = ByteBuffer.wrap(hdrBytes);

        // Read magic as little-endian first (most common)
        buf.order(ByteOrder.LITTLE_ENDIAN);
        int magic = buf.getInt(0);

        if (magic == PCAP_MAGIC_NATIVE) {
            needsByteSwap = false; // file is already little-endian
        } else if (magic == (int) PCAP_MAGIC_SWAPPED) {
            needsByteSwap = true;  // file is big-endian
            buf.order(ByteOrder.BIG_ENDIAN);
        } else {
            // Try interpreting magic as big-endian
            buf.order(ByteOrder.BIG_ENDIAN);
            int magicBE = buf.getInt(0);
            if (magicBE == PCAP_MAGIC_NATIVE) {
                needsByteSwap = false;
            } else {
                System.err.printf("Error: Invalid PCAP magic number: 0x%08X%n", magic);
                in.close();
                return false;
            }
        }

        versionMajor = buf.getShort(4) & 0xFFFF;
        versionMinor = buf.getShort(6) & 0xFFFF;
        // thiszone (4 bytes) at offset 8 — ignored
        // sigfigs  (4 bytes) at offset 12 — ignored
        snaplen = buf.getInt(16) & 0xFFFFFFFFL;
        network = buf.getInt(20) & 0xFFFFFFFFL;

        isOpen = true;

        System.out.println("Opened PCAP file: " + filename);
        System.out.println("  Version: " + versionMajor + "." + versionMinor);
        System.out.println("  Snaplen: " + snaplen + " bytes");
        System.out.println("  Link type: " + network + (network == 1 ? " (Ethernet)" : ""));

        return true;
    }


    public RawPacket readNextPacket() throws IOException {
        if (!isOpen) return null;

        // --- Read 16-byte packet header ---
        byte[] pktHdrBytes = new byte[16];
        int bytesRead = readFully(pktHdrBytes);
        if (bytesRead < 16) return null; // EOF

        ByteBuffer buf = ByteBuffer.wrap(pktHdrBytes);
        buf.order(needsByteSwap ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);

        long tsSec   = buf.getInt(0)  & 0xFFFFFFFFL;
        long tsUsec  = buf.getInt(4)  & 0xFFFFFFFFL;
        long inclLen = buf.getInt(8)  & 0xFFFFFFFFL;
        long origLen = buf.getInt(12) & 0xFFFFFFFFL;

        // Sanity check
        if (inclLen > snaplen || inclLen > 65535) {
            System.err.println("Error: Invalid packet length: " + inclLen);
            return null;
        }

        // --- Read packet data ---
        byte[] data = new byte[(int) inclLen];
        int dataRead = readFully(data);
        if (dataRead < (int) inclLen) {
            System.err.println("Error: Could not read packet data");
            return null;
        }

        return new RawPacket(tsSec, tsUsec, inclLen, origLen, data);
    }

    @Override
    public void close() throws IOException {
        if (in != null) {
            in.close();
            isOpen = false;
        }
    }

    public boolean isOpen()        { return isOpen; }
    public int  getVersionMajor()  { return versionMajor; }
    public int  getVersionMinor()  { return versionMinor; }
    public long getSnaplen()       { return snaplen; }
    public long getNetwork()       { return network; }
    public boolean needsByteSwap() { return needsByteSwap; }

    private int readFully(byte[] buf) throws IOException {
        int total = 0;
        while (total < buf.length) {
            int n = in.read(buf, total, buf.length - total);
            if (n == -1) break;
            total += n;
        }
        return total;
    }
}
