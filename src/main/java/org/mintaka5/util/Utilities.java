package org.mintaka5.util;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.zip.CRC32;

public class Utilities {
    public static String getWideIp() {
        Socket s = new Socket();
        try {
            s.connect(new InetSocketAddress("google.com", 80));
            return s.getLocalAddress().getHostAddress();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static String crc32(String in) {
        byte[] inB = in.getBytes(StandardCharsets.UTF_8);

        CRC32 c = new CRC32();
        c.update(inB);
        long cL = c.getValue();

        return Long.toHexString(cL);
    }

    public static long specialHash(String s) {
        int p = 31;
        int m = (int) (1e9 + 9);
        long hashValue = 0;
        long pPow = 1;
        for(char c : s.toCharArray()) {
            hashValue = (hashValue + (c - 'a' + 1) * pPow) % m;
            pPow = (pPow * p) % m;
        }

        return hashValue;
    }
}
