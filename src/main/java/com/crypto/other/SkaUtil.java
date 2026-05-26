package com.crypto.other;

/**
 * limoran 自定义安全密钥混淆工具类
 * 用于对明文、密钥和密文做二次扰动。
 */
public final class SkaUtil {

    public static final String ENCRYPT_PRIVATE = "private";
    public static final String ENCRYPT_PUBLIC = "public";
    private static final String PRINTABLE = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    private static final String PRIVATE_MAP = rotate(PRINTABLE, 17);
    private static final String PUBLIC_MAP = rotate(PRINTABLE, 41);

    private SkaUtil() {
    }

    /**
     * limoran 使用私密模式加密。
     * @param plaintext 待加密的明文
     * @return 加密结果
     */
    public static String encrypt(String plaintext) {
        return encrypt(ENCRYPT_PRIVATE, plaintext);
    }

    /**
     * limoran 按指定模式加密。
     * @param mode 加密模式
     * @param plaintext 待加密的明文
     * @return 加密结果
     */
    public static String encrypt(String mode, String plaintext) {
        if (plaintext == null) {
            return "";
        }
        return translate(plaintext, PRINTABLE, getToMap(mode));
    }

    /**
     * limoran 使用私密模式解密。
     * @param cipher 待解密的密文
     * @return 解密结果
     */
    public static String decrypt(String cipher) {
        return decrypt(ENCRYPT_PRIVATE, cipher);
    }

    /**
     * limoran 按指定模式解密。
     * @param mode 解密模式
     * @param cipher 待解密的密文
     * @return 解密结果
     */
    public static String decrypt(String mode, String cipher) {
        if (cipher == null) {
            return "";
        }
        return translate(cipher, getToMap(mode), PRINTABLE);
    }

    private static String getToMap(String mode) {
        if (ENCRYPT_PUBLIC.equalsIgnoreCase(mode)) {
            return PUBLIC_MAP;
        }
        return PRIVATE_MAP;
    }

    private static String translate(String text, String from, String to) {
        StringBuilder builder = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            int index = from.indexOf(c);
            if (index < 0) {
                builder.append(c);
                continue;
            }
            builder.append(to.charAt(index));
        }
        return builder.toString();
    }

    private static String rotate(String value, int offset) {
        int len = value.length();
        int actual = offset % len;
        if (actual < 0) {
            actual += len;
        }
        return value.substring(actual) + value.substring(0, actual);
    }
}
