package com.crypto.other;

/**
 * limoran 统一哈希工具类
 * 对外集中提供MD5、SHA、SM3与组合哈希校验能力。
 */
public final class HashUtil {

    private HashUtil() {
    }

    /**
     * limoran 计算字符串的MD5摘要。
     * @param text 待计算的文本
     * @return MD5摘要的十六进制字符串
     * @author limoran
     */
    public static String md5(String text) {
        return DigestUtil.md5(text);
    }

    /**
     * limoran 计算文件的MD5摘要。
     * @param path 文件路径
     * @return MD5摘要的十六进制字符串
     * @author limoran
     */
    public static String md5File(String path) {
        return DigestUtil.md5File(path);
    }

    /**
     * limoran 计算字符串的SHA-1摘要。
     * @param text 待计算的文本
     * @return SHA-1摘要的十六进制字符串
     * @author limoran
     */
    public static String sha1(String text) {
        return DigestUtil.sha1(text);
    }

    /**
     * limoran 计算字符串的SHA-256摘要。
     * @param text 待计算的文本
     * @return SHA-256摘要的十六进制字符串
     * @author limoran
     */
    public static String sha256(String text) {
        return DigestUtil.sha256(text);
    }

    /**
     * limoran 计算字符串的SHA-384摘要。
     * @param text 待计算的文本
     * @return SHA-384摘要的十六进制字符串
     * @author limoran
     */
    public static String sha384(String text) {
        return DigestUtil.sha384(text);
    }

    /**
     * limoran 计算字符串的SHA-512摘要。
     * @param text 待计算的文本
     * @return SHA-512摘要的十六进制字符串
     * @author limoran
     */
    public static String sha512(String text) {
        return DigestUtil.sha512(text);
    }

    /**
     * limoran 计算字符串的SM3摘要。
     * @param text 待计算的文本
     * @return SM3摘要的十六进制字符串
     * @author limoran
     */
    public static String sm3(String text) {
        return DigestUtil.sm3(text);
    }

    /**
     * limoran 计算文件的SM3摘要。
     * @param path 文件路径
     * @return SM3摘要的十六进制字符串
     * @author limoran
     */
    public static String sm3File(String path) {
        return DigestUtil.sm3File(path);
    }

    /**
     * limoran 对字符串执行多次MD5。
     * @param text 待计算的文本
     * @param times 计算次数
     * @return 最终MD5摘要的十六进制字符串
     * @author limoran
     */
    public static String repeatMd5(String text, int times) {
        if (times <= 0) {
            times = 1;
        }
        String result = md5(text);
        for (int i = 1; i < times; i++) {
            result = md5(result);
        }
        return result;
    }

    /**
     * limoran 校验字符串是否匹配MD5摘要。
     * @param text 原文
     * @param hash MD5摘要
     * @return 匹配返回true，否则返回false
     * @author limoran
     */
    public static boolean checkMd5(String text, String hash) {
        if (text == null || hash == null) {
            return false;
        }
        return md5(text).equalsIgnoreCase(hash);
    }

    /**
     * limoran 校验字符串是否匹配SM3摘要。
     * @param text 原文
     * @param hash SM3摘要
     * @return 匹配返回true，否则返回false
     * @author limoran
     */
    public static boolean checkSm3(String text, String hash) {
        if (text == null || hash == null) {
            return false;
        }
        return sm3(text).equalsIgnoreCase(hash);
    }
}
