package com.crypto.aesrsa;

import com.crypto.other.Base64Util;
import com.crypto.other.RandomUtil;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * limoran AES加解密工具类
 * 支持字符串、字节数组和文件的AES处理。
 */
public final class AesUtil {

    private static final String ALGORITHM = "AES";
    private static final String DEFAULT_MODE = "ECB";
    private static final String DEFAULT_PADDING = "PKCS5Padding";
    private static final String DEFAULT_IV = "ASDFGHJKL8899000";

    private AesUtil() {
    }

    /**
     * limoran 生成AES密钥。
     * @return 16位随机密钥
     * @author limoran
     */
    public static String generateKey() {
        return RandomUtil.alnum(16);
    }

    /**
     * limoran 使用默认IV和默认模式加密字符串。
     * @param key 加密密钥
     * @param plaintext 待加密文本
     * @return Base64编码后的密文
     * @author limoran
     */
    public static String encrypt(String key, String plaintext) {
        return encrypt(key, DEFAULT_IV, plaintext, DEFAULT_MODE, DEFAULT_PADDING);
    }

    /**
     * limoran 使用指定IV和CBC模式加密字符串。
     * @param key 加密密钥
     * @param iv 初始化向量
     * @param plaintext 待加密文本
     * @return Base64编码后的密文
     * @author limoran
     */
    public static String encrypt(String key, String iv, String plaintext) {
        return encrypt(key, iv, plaintext, "CBC", DEFAULT_PADDING);
    }

    /**
     * limoran 按指定模式和填充方式加密字符串。
     * @param key 加密密钥
     * @param iv 初始化向量
     * @param plaintext 待加密文本
     * @param mode 分组模式
     * @param padding 填充方式
     * @return Base64编码后的密文
     * @author limoran
     */
    public static String encrypt(String key, String iv, String plaintext, String mode, String padding) {
        byte[] encrypted = encryptBytes(key, iv, plaintext == null ? new byte[0] : plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8), mode, padding);
        return Base64Util.encode(encrypted);
    }

    /**
     * limoran 使用默认IV和CBC模式加密字节数组。
     * @param key 加密密钥
     * @param plaintext 待加密字节数组
     * @return 加密后的字节数组
     * @author limoran
     */
    public static byte[] encryptBytes(String key, byte[] plaintext) {
        return encryptBytes(key, DEFAULT_IV, plaintext, "CBC", DEFAULT_PADDING);
    }

    /**
     * limoran 按指定参数加密字节数组。
     * @param key 加密密钥
     * @param iv 初始化向量
     * @param plaintext 待加密字节数组
     * @param mode 分组模式
     * @param padding 填充方式
     * @return 加密后的字节数组
     * @author limoran
     */
    public static byte[] encryptBytes(String key, String iv, byte[] plaintext, String mode, String padding) {
        try {
            Cipher cipher = buildCipher(Cipher.ENCRYPT_MODE, key, iv, mode, padding);
            return cipher.doFinal(plaintext == null ? new byte[0] : plaintext);
        } catch (Throwable throwable) {
            return new byte[0];
        }
    }

    /**
     * limoran 使用默认IV和默认模式解密字符串。
     * @param key 解密密钥
     * @param cipherText Base64编码密文
     * @return 解密后的明文
     * @author limoran
     */
    public static String decrypt(String key, String cipherText) {
        return decrypt(key, DEFAULT_IV, cipherText, DEFAULT_MODE, DEFAULT_PADDING);
    }

    /**
     * limoran 使用指定IV和CBC模式解密字符串。
     * @param key 解密密钥
     * @param iv 初始化向量
     * @param cipherText Base64编码密文
     * @return 解密后的明文
     * @author limoran
     */
    public static String decrypt(String key, String iv, String cipherText) {
        return decrypt(key, iv, cipherText, "CBC", DEFAULT_PADDING);
    }

    /**
     * limoran 按指定模式和填充方式解密字符串。
     * @param key 解密密钥
     * @param iv 初始化向量
     * @param cipherText Base64编码密文
     * @param mode 分组模式
     * @param padding 填充方式
     * @return 解密后的明文
     * @author limoran
     */
    public static String decrypt(String key, String iv, String cipherText, String mode, String padding) {
        byte[] decrypted = decryptBytes(key, iv, Base64Util.decode(cipherText), mode, padding);
        return new String(decrypted, java.nio.charset.StandardCharsets.UTF_8);
    }

    /**
     * limoran 使用默认IV和CBC模式解密字节数组。
     * @param key 解密密钥
     * @param cipherBytes 待解密字节数组
     * @return 解密后的字节数组
     * @author limoran
     */
    public static byte[] decryptBytes(String key, byte[] cipherBytes) {
        return decryptBytes(key, DEFAULT_IV, cipherBytes, "CBC", DEFAULT_PADDING);
    }

    /**
     * limoran 按指定参数解密字节数组。
     * @param key 解密密钥
     * @param iv 初始化向量
     * @param cipherBytes 待解密字节数组
     * @param mode 分组模式
     * @param padding 填充方式
     * @return 解密后的字节数组
     * @author limoran
     */
    public static byte[] decryptBytes(String key, String iv, byte[] cipherBytes, String mode, String padding) {
        try {
            Cipher cipher = buildCipher(Cipher.DECRYPT_MODE, key, iv, mode, padding);
            return cipher.doFinal(cipherBytes == null ? new byte[0] : cipherBytes);
        } catch (Throwable throwable) {
            return new byte[0];
        }
    }

    /**
     * limoran 使用默认参数加密文件。
     * @param key 加密密钥
     * @param sourcePath 源文件路径
     * @param targetPath 目标文件路径
     * @return 生成的目标文件路径，失败返回null
     * @author limoran
     */
    public static Path encryptFile(String key, String sourcePath, String targetPath) {
        return encryptFile(key, DEFAULT_IV, sourcePath, targetPath, "CBC", DEFAULT_PADDING);
    }

    /**
     * limoran 按指定参数加密文件。
     * @param key 加密密钥
     * @param iv 初始化向量
     * @param sourcePath 源文件路径
     * @param targetPath 目标文件路径
     * @param mode 分组模式
     * @param padding 填充方式
     * @return 生成的目标文件路径，失败返回null
     * @author limoran
     */
    public static Path encryptFile(String key, String iv, String sourcePath, String targetPath, String mode, String padding) {
        return transformFile(Cipher.ENCRYPT_MODE, key, iv, sourcePath, targetPath, mode, padding);
    }

    /**
     * limoran 使用默认参数解密文件。
     * @param key 解密密钥
     * @param sourcePath 源文件路径
     * @param targetPath 目标文件路径
     * @return 生成的目标文件路径，失败返回null
     * @author limoran
     */
    public static Path decryptFile(String key, String sourcePath, String targetPath) {
        return decryptFile(key, DEFAULT_IV, sourcePath, targetPath, "CBC", DEFAULT_PADDING);
    }

    /**
     * limoran 按指定参数解密文件。
     * @param key 解密密钥
     * @param iv 初始化向量
     * @param sourcePath 源文件路径
     * @param targetPath 目标文件路径
     * @param mode 分组模式
     * @param padding 填充方式
     * @return 生成的目标文件路径，失败返回null
     * @author limoran
     */
    public static Path decryptFile(String key, String iv, String sourcePath, String targetPath, String mode, String padding) {
        return transformFile(Cipher.DECRYPT_MODE, key, iv, sourcePath, targetPath, mode, padding);
    }

    /**
     * limoran 执行文件级加解密转换。
     * @param cipherMode Cipher模式
     * @param key 密钥
     * @param iv 初始化向量
     * @param sourcePath 源文件路径
     * @param targetPath 目标文件路径
     * @param mode 分组模式
     * @param padding 填充方式
     * @return 生成的目标文件路径，失败返回null
     * @author limoran
     */
    private static Path transformFile(int cipherMode, String key, String iv, String sourcePath, String targetPath, String mode, String padding) {
        if (sourcePath == null || targetPath == null) {
            return null;
        }
        Path source = Paths.get(sourcePath);
        Path target = Paths.get(targetPath);
        try (InputStream inputStream = Files.newInputStream(source);
             OutputStream outputStream = Files.newOutputStream(target)) {
            Cipher cipher = buildCipher(cipherMode, key, iv, mode, padding);
            if (cipherMode == Cipher.ENCRYPT_MODE) {
                try (CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher)) {
                    byte[] buffer = new byte[8192];
                    int read;
                    while ((read = inputStream.read(buffer)) != -1) {
                        cipherOutputStream.write(buffer, 0, read);
                    }
                    cipherOutputStream.flush();
                }
            } else {
                try (CipherInputStream cipherInputStream = new CipherInputStream(inputStream, cipher)) {
                    byte[] buffer = new byte[8192];
                    int read;
                    while ((read = cipherInputStream.read(buffer)) != -1) {
                        outputStream.write(buffer, 0, read);
                    }
                    outputStream.flush();
                }
            }
            return target;
        } catch (IOException | GeneralSecurityException e) {
            return null;
        }
    }

    /**
     * limoran 构建AES Cipher实例。
     * @param cipherMode Cipher模式
     * @param key 密钥
     * @param iv 初始化向量
     * @param mode 分组模式
     * @param padding 填充方式
     * @return Cipher实例
     * @author limoran
     */
    private static Cipher buildCipher(int cipherMode, String key, String iv, String mode, String padding) throws GeneralSecurityException {
        byte[] keyBytes = normalizeKey(key);
        String effectiveMode = mode == null || mode.length() == 0 ? DEFAULT_MODE : mode;
        String effectivePadding = padding == null || padding.length() == 0 ? DEFAULT_PADDING : padding;
        String transformation = ALGORITHM + "/" + effectiveMode + "/" + effectivePadding;
        Cipher cipher = Cipher.getInstance(transformation);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, ALGORITHM);
        if ("ECB".equalsIgnoreCase(effectiveMode)) {
            cipher.init(cipherMode, keySpec);
            return cipher;
        }
        IvParameterSpec ivParameterSpec = new IvParameterSpec(normalizeIv(iv));
        cipher.init(cipherMode, keySpec, ivParameterSpec);
        return cipher;
    }

    /**
     * limoran 规范化AES密钥长度。
     * @param key 原始密钥
     * @return 规范化后的密钥字节数组
     * @author limoran
     */
    private static byte[] normalizeKey(String key) {
        byte[] bytes = key == null ? new byte[0] : key.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        int size;
        if (bytes.length <= 16) {
            size = 16;
        } else if (bytes.length <= 24) {
            size = 24;
        } else {
            size = 32;
        }
        return Arrays.copyOf(bytes, size);
    }

    /**
     * limoran 规范化AES初始化向量长度。
     * @param iv 原始初始化向量
     * @return 规范化后的初始化向量字节数组
     * @author limoran
     */
    private static byte[] normalizeIv(String iv) {
        byte[] bytes = iv == null ? DEFAULT_IV.getBytes(java.nio.charset.StandardCharsets.UTF_8) : iv.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        return Arrays.copyOf(bytes, 16);
    }
}
