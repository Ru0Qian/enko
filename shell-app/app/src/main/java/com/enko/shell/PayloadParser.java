package com.enko.shell;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

final class PayloadParser {
    private static final byte[] PACKAGE_MAGIC_X = new byte[] {
            (byte)0x0C, (byte)0x11, (byte)0x2C, (byte)0x38,
            (byte)0x46, (byte)0x40, (byte)0x73, (byte)0x68,
            (byte)0x8D, (byte)0xBE, (byte)0xA3, (byte)0xCD,
            (byte)0xCB, (byte)0xE6, (byte)0xEA, (byte)0x6C,
            (byte)0x12, (byte)0x24, (byte)0x55
    };

    static final class DexEntry {
        final String name;
        final byte[] data;

        DexEntry(String name, byte[] data) {
            this.name = name;
            this.data = data;
        }
    }

    private PayloadParser() {
    }

    static List<DexEntry> parse(byte[] plain) throws IOException {
        ByteArrayInputStream in = new ByteArrayInputStream(plain);
        byte[] header = readExactly(in, PACKAGE_MAGIC_X.length);
        for (int i = 0; i < PACKAGE_MAGIC_X.length; i++) {
            if (header[i] != packageMagicAt(i)) {
                throw new IOException("package magic mismatch");
            }
        }

        int fileCount = readU32(in);
        if (fileCount <= 0) {
            throw new IOException("invalid dex count: " + fileCount);
        }

        List<DexEntry> out = new ArrayList<>(fileCount);
        for (int i = 0; i < fileCount; i++) {
            int nameLen = readU16(in);
            String name = new String(readExactly(in, nameLen), StandardCharsets.UTF_8);
            int dataLen = readU32(in);
            byte[] data = readExactly(in, dataLen);
            out.add(new DexEntry(name, data));
        }
        return out;
    }

    private static int readU16(ByteArrayInputStream in) throws IOException {
        byte[] b = readExactly(in, 2);
        return ((b[0] & 0xFF) << 8) | (b[1] & 0xFF);
    }

    private static byte packageMagicAt(int index) {
        return (byte) (PACKAGE_MAGIC_X[index] ^ 0x5D ^ ((index * 17 + 7) & 0xFF));
    }

    private static int readU32(ByteArrayInputStream in) throws IOException {
        byte[] b = readExactly(in, 4);
        return ((b[0] & 0xFF) << 24)
                | ((b[1] & 0xFF) << 16)
                | ((b[2] & 0xFF) << 8)
                | (b[3] & 0xFF);
    }

    private static byte[] readExactly(ByteArrayInputStream in, int len) throws IOException {
        if (len < 0) {
            throw new IOException("negative length");
        }
        byte[] out = new byte[len];
        int total = 0;
        while (total < len) {
            int n = in.read(out, total, len - total);
            if (n < 0) {
                throw new IOException("unexpected eof");
            }
            total += n;
        }
        return out;
    }
}
