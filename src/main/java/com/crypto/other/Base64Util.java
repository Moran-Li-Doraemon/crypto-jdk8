package com.crypto.other;

import java.util.Base64;

/**
 * limoran Base64编解码工具类
 * 提供字符串与字节数组的Base64编码、解码能力。
 */
public final class Base64Util {

    private Base64Util() {
    }

    /**
     * limoran 将字节数组编码为Base64字符串。
     * @param bytes 源字节数组
     * @return Base64字符串
     */
    public static String encode(byte[] bytes) {
        if (bytes == null) {
            return "";
        }
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * limoran 将Base64字符串解码为字节数组。
     * @param value Base64字符串
     * @return 解码后的字节数组
     */
    public static byte[] decode(String value) {
        if (value == null || value.length() == 0) {
            return new byte[0];
        }
        return Base64.getDecoder().decode(value);
    }

    /**
     * limoran 将普通字符串编码为Base64字符串。
     * @param value 待编码字符串
     * @return Base64字符串
     */
    public static String encode(String value) {
        if (value == null) {
            return "";
        }
        return encode(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * limoran 将Base64字符串解码为普通字符串。
     * @param value Base64字符串
     * @return 原始字符串
     */
    public static String decodeToString(String value) {
        byte[] bytes = decode(value);
        return new String(bytes, java.nio.charset.StandardCharsets.UTF_8);
    }
}
