package com.crypto.other;

/**
 * limoran 凯撒偏移混淆工具类
 * 仅处理字母与数字字符。
 */
public final class CaesarUtil {

    private CaesarUtil() {
    }

    /**
     * limoran 使用默认偏移量加密。
     * @param plaintext 待加密的明文
     * @return 加密结果
     */
    public static String encrypt(String plaintext) {
        return encrypt(plaintext, 30);
    }

    /**
     * limoran 按指定偏移量加密。
     * @param plaintext 待加密的明文
     * @param offset 偏移量
     * @return 加密结果
     */
    public static String encrypt(String plaintext, int offset) {
        if (plaintext == null) {
            return "";
        }
        StringBuilder builder = new StringBuilder(plaintext.length());
        for (int i = 0; i < plaintext.length(); i++) {
            char c = plaintext.charAt(i);
            if (c >= 'a' && c <= 'z') {
                c += offset % 26;
                if (c < 'a') {
                    c += 26;
                }
                if (c > 'z') {
                    c -= 26;
                }
            } else if (c >= 'A' && c <= 'Z') {
                c += offset % 26;
                if (c < 'A') {
                    c += 26;
                }
                if (c > 'Z') {
                    c -= 26;
                }
            } else if (c >= '0' && c <= '9') {
                c += offset % 10;
                if (c < '0') {
                    c += 10;
                }
                if (c > '9') {
                    c -= 10;
                }
            }
            builder.append(c);
        }
        return builder.toString();
    }

    /**
     * limoran 使用默认偏移量解密。
     * @param cipher 待解密的密文
     * @return 解密结果
     */
    public static String decrypt(String cipher) {
        return decrypt(cipher, 30);
    }

    /**
     * limoran 按指定偏移量解密。
     * @param cipher 待解密的密文
     * @param offset 偏移量
     * @return 解密结果
     */
    public static String decrypt(String cipher, int offset) {
        if (cipher == null) {
            return "";
        }
        return encrypt(cipher, 0 - offset);
    }
}
