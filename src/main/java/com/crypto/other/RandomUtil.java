package com.crypto.other;

import java.security.SecureRandom;

/**
 * limoran 随机字符串工具类
 * 提供字母数字、可打印字符和随机字节数组生成能力。
 */
public final class RandomUtil {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private static final String PRINTABLE = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

    private RandomUtil() {
    }

    /**
     * limoran 生成指定长度的字母数字随机串。
     * @param length 长度
     * @return 随机串
     */
    public static String alnum(int length) {
        if (length <= 0) {
            return "";
        }
        StringBuilder builder = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            builder.append(ALNUM.charAt(RANDOM.nextInt(ALNUM.length())));
        }
        return builder.toString();
    }

    /**
     * limoran 生成指定长度的可打印ASCII随机串。
     * @param length 长度
     * @return 随机串
     */
    public static String printable(int length) {
        if (length <= 0) {
            return "";
        }
        StringBuilder builder = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            builder.append(PRINTABLE.charAt(RANDOM.nextInt(PRINTABLE.length())));
        }
        return builder.toString();
    }

    /**
     * limoran 生成指定长度的随机字节数组。
     * @param length 长度
     * @return 随机字节数组
     */
    public static byte[] bytes(int length) {
        if (length <= 0) {
            return new byte[0];
        }
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }
}
