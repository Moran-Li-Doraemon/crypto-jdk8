package com.crypto.other;

import com.crypto.other.HashUtil;
import com.crypto.other.Base64Util;
import com.crypto.other.RandomUtil;

/**
 * limoran 字符串淹没混淆工具类
 * 通过倒序、随机串、校验前缀和二次混淆提升阅读难度。
 */
public final class SubmergeUtil {

    private SubmergeUtil() {
    }

    /**
     * limoran 生成默认长度的密钥。
     * @return 密钥
     */
    public static String generateKey() {
        return RandomUtil.printable(256);
    }

    /**
     * limoran 生成指定长度的密钥。
     * @param length 密钥长度
     * @return 密钥
     */
    public static String generateKey(int length) {
        if (length < 128) {
            return "";
        }
        return RandomUtil.printable(length);
    }

    /**
     * limoran 对字符串进行淹没加密。
     * @param key 密钥
     * @param plaintext 待加密的明文
     * @return 加密结果
     */
    public static String encrypt(String key, String plaintext) {
        if (key == null || plaintext == null) {
            return "";
        }
        String reversed = new StringBuilder(plaintext).reverse().toString();
        String body = Base64Util.encode(RandomUtil.bytes(12)) + "." + reversed + "." + plaintext.length();
        body = SkaUtil.encrypt(SkaUtil.ENCRYPT_PUBLIC, body);
        return HashUtil.sha512(key) + HashUtil.sha512(body) + body;
    }

    /**
     * limoran 对字符串进行淹没解密。
     * @param key 密钥
     * @param cipher 待解密的密文
     * @return 解密结果
     */
    public static String decrypt(String key, String cipher) {
        if (key == null || cipher == null || cipher.length() <= 256) {
            return "";
        }
        String keyHash = cipher.substring(0, 128);
        String bodyHash = cipher.substring(128, 256);
        String body = cipher.substring(256);
        if (!keyHash.equalsIgnoreCase(HashUtil.sha512(key))) {
            return "";
        }
        if (!bodyHash.equalsIgnoreCase(HashUtil.sha512(body))) {
            return "";
        }
        body = SkaUtil.decrypt(SkaUtil.ENCRYPT_PUBLIC, body);
        int lastIndex = body.lastIndexOf('.');
        int firstIndex = body.indexOf('.');
        if (firstIndex < 0 || lastIndex <= firstIndex) {
            return "";
        }
        String reversed = body.substring(firstIndex + 1, lastIndex);
        String lenText = body.substring(lastIndex + 1);
        int length;
        try {
            length = Integer.parseInt(lenText);
        } catch (Throwable throwable) {
            return "";
        }
        if (reversed.length() != length) {
            return "";
        }
        return new StringBuilder(reversed).reverse().toString();
    }
}
