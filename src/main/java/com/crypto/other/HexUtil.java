package com.crypto.other;

/**
 * limoran 十六进制转换工具类
 * 提供字节数组与hex字符串互转能力。
 */
public final class HexUtil {

    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();

    private HexUtil() {
    }

    /**
     * limoran 字节数组转十六进制字符串。
     * @param bytes 源字节数组
     * @return hex字符串
     */
    public static String toHex(byte[] bytes) {
        if (bytes == null) {
            return "";
        }
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 255;
            hexChars[i * 2] = HEX_ARRAY[v >>> 4];
            hexChars[i * 2 + 1] = HEX_ARRAY[v & 15];
        }
        return new String(hexChars);
    }

    /**
     * limoran 十六进制字符串转字节数组。
     * @param value hex字符串
     * @return 字节数组
     */
    public static byte[] fromHex(String value) {
        if (value == null || value.length() == 0) {
            return new byte[0];
        }
        String hex = value.trim();
        if ((hex.length() & 1) == 1) {
            throw new IllegalArgumentException("hex length must be even");
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            int high = Character.digit(hex.charAt(i), 16);
            int low = Character.digit(hex.charAt(i + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("invalid hex");
            }
            out[i / 2] = (byte) ((high << 4) + low);
        }
        return out;
    }
}
