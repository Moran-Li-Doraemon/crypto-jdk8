package com.crypto.gm;

import com.crypto.other.DigestUtil;
import com.crypto.other.HexUtil;

/**
 * limoran SM3摘要工具类
 * 支持字符串、字节数组和文件的SM3计算。
 */
public final class Sm3Util {

    private Sm3Util() {
    }

    /**
     * limoran 计算字符串的SM3摘要。
     * @param text 待计算的文本
     * @return SM3摘要的十六进制字符串
     * @author limoran
     */
    public static String hash(String text) {
        return DigestUtil.sm3(text);
    }

    /**
     * limoran 计算字节数组的SM3摘要。
     * @param bytes 待计算的字节数组
     * @return SM3摘要的十六进制字符串
     * @author limoran
     */
    public static String hash(byte[] bytes) {
        return DigestUtil.sm3(bytes);
    }

    /**
     * limoran 计算文件的SM3摘要。
     * @param path 文件路径
     * @return SM3摘要的十六进制字符串
     * @author limoran
     */
    public static String hashFile(String path) {
        return DigestUtil.sm3File(path);
    }

    /**
     * limoran 通过输入流计算SM3摘要。
     * @param inputStream 输入流
     * @return SM3摘要的十六进制字符串
     * @author limoran
     */
    public static String hashStream(java.io.InputStream inputStream) {
        if (inputStream == null) {
            return "";
        }
        try {
            org.bouncycastle.crypto.digests.SM3Digest digest = new org.bouncycastle.crypto.digests.SM3Digest();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = inputStream.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
            byte[] hash = new byte[digest.getDigestSize()];
            digest.doFinal(hash, 0);
            return HexUtil.toHex(hash);
        } catch (java.io.IOException e) {
            return "";
        }
    }

    /**
     * limoran 校验字符串是否匹配SM3摘要。
     * @param text 原文
     * @param hash SM3摘要
     * @return 匹配返回true，否则返回false
     * @author limoran
     */
    public static boolean verify(String text, String hash) {
        if (text == null || hash == null || hash.length() == 0) {
            return false;
        }
        return hash(text).equalsIgnoreCase(hash);
    }
}
