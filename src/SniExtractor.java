package dpi;

public class SniExtractor {

    // TLS record content types
    private static final int CONTENT_TYPE_HANDSHAKE = 0x16;

    // TLS handshake message types
    private static final int HANDSHAKE_CLIENT_HELLO = 0x01;

    // TLS extension types
    private static final int EXTENSION_SNI     = 0x0000;
    private static final int SNI_TYPE_HOSTNAME = 0x00;

    public static String extract(byte[] payload, int offset, int length) {
        if (!isTlsClientHello(payload, offset, length)) return null;

        // Skip TLS record header (5 bytes) + handshake header (4 bytes)
        // = 9 bytes total before Client Hello body
        int pos = offset + 9;

        // Skip Client Version (2)
        pos += 2;

        // Skip Random (32)
        pos += 32;

        // Skip Session ID
        if (pos >= offset + length) return null;
        int sessionIdLen = payload[pos] & 0xFF;
        pos += 1 + sessionIdLen;

        // Skip Cipher Suites
        if (pos + 2 > offset + length) return null;
        int cipherSuitesLen = PacketParser.readUint16BE(payload, pos);
        pos += 2 + cipherSuitesLen;

        // Skip Compression Methods
        if (pos >= offset + length) return null;
        int compressionLen = payload[pos] & 0xFF;
        pos += 1 + compressionLen;

        // Extensions
        if (pos + 2 > offset + length) return null;
        int extensionsLen = PacketParser.readUint16BE(payload, pos);
        pos += 2;

        int extensionsEnd = pos + extensionsLen;
        if (extensionsEnd > offset + length) extensionsEnd = offset + length;

        // Walk extensions looking for SNI (type 0x0000)
        while (pos + 4 <= extensionsEnd) {
            int extType   = PacketParser.readUint16BE(payload, pos);
            int extLen    = PacketParser.readUint16BE(payload, pos + 2);
            pos += 4;

            if (pos + extLen > extensionsEnd) break;

            if (extType == EXTENSION_SNI) {
                // SNI extension structure:
                //   SNI List Length (2) | SNI Type (1) | SNI Length (2) | hostname
                if (extLen < 5) break;

                int sniType = payload[pos + 2] & 0xFF;
                if (sniType != SNI_TYPE_HOSTNAME) break;

                int sniLen = PacketParser.readUint16BE(payload, pos + 3);
                if (pos + 5 + sniLen > extensionsEnd) break;

                return new String(payload, pos + 5, sniLen);
            }

            pos += extLen;
        }

        return null; // SNI extension not found in this Client Hello
    }

    /** Convenience overload that uses the full byte array. */
    public static String extract(byte[] payload) {
        return extract(payload, 0, payload.length);
    }


    public static boolean isTlsClientHello(byte[] payload, int offset, int length) {
        if (length < 9) return false;

        // Content type must be Handshake (0x16)
        if ((payload[offset] & 0xFF) != CONTENT_TYPE_HANDSHAKE) return false;

        // TLS version must be 0x0300..0x0304
        int version = PacketParser.readUint16BE(payload, offset + 1);
        if (version < 0x0300 || version > 0x0304) return false;

        // Record length sanity
        int recordLen = PacketParser.readUint16BE(payload, offset + 3);
        if (recordLen > length - 5) return false;

        // Handshake type must be Client Hello (0x01)
        return (payload[offset + 5] & 0xFF) == HANDSHAKE_CLIENT_HELLO;
    }

    public static String extractHttpHost(byte[] payload, int offset, int length) {
        if (!isHttpRequest(payload, offset, length)) return null;

        // Search for "Host:" (case-insensitive)
        int end = offset + length;
        for (int i = offset; i + 5 < end; i++) {
            if (matchesIgnoreCase(payload, i, "Host:")) {
                // Skip "Host:" and any leading whitespace
                int start = i + 5;
                while (start < end && (payload[start] == ' ' || payload[start] == '\t')) {
                    start++;
                }

                // Find end of line
                int lineEnd = start;
                while (lineEnd < end && payload[lineEnd] != '\r' && payload[lineEnd] != '\n') {
                    lineEnd++;
                }

                if (lineEnd > start) {
                    String host = new String(payload, start, lineEnd - start).trim();
                    // Strip port if present (e.g. "example.com:8080" → "example.com")
                    int colon = host.indexOf(':');
                    if (colon >= 0) host = host.substring(0, colon);
                    return host;
                }
            }
        }

        return null;
    }

    public static boolean isHttpRequest(byte[] payload, int offset, int length) {
        if (length < 4) return false;
        String[] methods = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};
        for (String m : methods) {
            if (matchesIgnoreCase(payload, offset, m)) return true;
        }
        return false;
    }

    public static boolean isDnsQuery(byte[] payload, int offset, int length) {
        if (length < 12) return false;
        // QR bit (bit 7 of byte 2) = 0 means query
        if ((payload[offset + 2] & 0x80) != 0) return false;
        // QDCOUNT (bytes 4-5) must be > 0
        int qdcount = PacketParser.readUint16BE(payload, offset + 4);
        return qdcount > 0;
    }

    public static String extractDnsQuery(byte[] payload, int offset, int length) {
        if (!isDnsQuery(payload, offset, length)) return null;

        int pos = offset + 12; // DNS header is 12 bytes
        int end = offset + length;
        StringBuilder domain = new StringBuilder();

        while (pos < end) {
            int labelLen = payload[pos] & 0xFF;
            if (labelLen == 0) break;        // end of name
            if (labelLen > 63) break;        // compression pointer or invalid

            pos++;
            if (pos + labelLen > end) break;

            if (domain.length() > 0) domain.append('.');
            domain.append(new String(payload, pos, labelLen));
            pos += labelLen;
        }

        return (domain.length() > 0) ? domain.toString() : null;
    }

    private static boolean matchesIgnoreCase(byte[] payload, int offset, String s) {
        if (offset + s.length() > payload.length) return false;
        for (int i = 0; i < s.length(); i++) {
            char pc = (char) (payload[offset + i] & 0xFF);
            char sc = s.charAt(i);
            if (Character.toLowerCase(pc) != Character.toLowerCase(sc)) return false;
        }
        return true;
    }
}
