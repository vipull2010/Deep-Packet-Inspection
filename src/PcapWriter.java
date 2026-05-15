package dpi;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PcapWriter implements Closeable {

    private static final int PCAP_MAGIC   = 0xa1b2c3d4;
    private static final int VERSION_MAJ  = 2;
    private static final int VERSION_MIN  = 4;
    private static final int SNAPLEN      = 65535;
    private static final int LINK_ETHERNET = 1;

    private OutputStream out;

    public void open(String filename) throws IOException {
        out = new BufferedOutputStream(new FileOutputStream(filename));
        writeGlobalHeader();
    }

    public void writePacket(RawPacket pkt) throws IOException {
        // Packet header: ts_sec(4) ts_usec(4) incl_len(4) orig_len(4)
        ByteBuffer buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt((int) pkt.tsSec);
        buf.putInt((int) pkt.tsUsec);
        buf.putInt((int) pkt.inclLen);
        buf.putInt((int) pkt.origLen);
        out.write(buf.array());
        out.write(pkt.data, 0, (int) pkt.inclLen);
    }

    @Override
    public void close() throws IOException {
        if (out != null) {
            out.flush();
            out.close();
        }
    }

    // -------------------------------------------------------------------------

    private void writeGlobalHeader() throws IOException {
        // Global header: magic(4) ver_maj(2) ver_min(2) thiszone(4)
        //                sigfigs(4) snaplen(4) network(4) = 24 bytes total
        ByteBuffer buf = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN);
        buf.putInt(PCAP_MAGIC);
        buf.putShort((short) VERSION_MAJ);
        buf.putShort((short) VERSION_MIN);
        buf.putInt(0);          // thiszone
        buf.putInt(0);          // sigfigs
        buf.putInt(SNAPLEN);
        buf.putInt(LINK_ETHERNET);
        out.write(buf.array());
    }
}
