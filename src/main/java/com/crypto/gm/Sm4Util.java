package com.crypto.gm;

import com.crypto.other.Base64Util;
import com.crypto.other.ProviderUtil;
import com.crypto.other.RandomUtil;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * limoran SM4加解密工具类
 * 支持字符串、字节数组和文件的SM4处理。
 */
public final class Sm4Util {

    private static final String ALGORITHM = "SM4";
    private static final String DEFAULT_MODE = "CBC";
    private static final String DEFAULT_PADDING = "PKCS5Padding";
    private static final String DEFAULT_IV = "ASDFGHJKL8899000";

    private Sm4Util() {
    }

    /**
     * limoran 生成SM4密钥。
     * @return Base64编码的密钥字符串，失败时返回随机字符串
     * @author limoran
     */
    public static String generateKey() {
        ProviderUtil.ensureBouncyCastle();
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM, "BC");
            keyGenerator.init(128, new SecureRandom());
            SecretKey secretKey = keyGenerator.generateKey();
            return Base64Util.encode(secretKey.getEncoded());
        } catch (Throwable throwable) {
            return RandomUtil.alnum(16);
        }
    }

    /**
     * limoran 使用默认参数加密字符串。
     * @param key 加密密钥
     * @param plaintext 待加密文本
     * @return Base64编码后的密文
     * @author limoran
     */
    public static String encrypt(String key, String plaintext) {
        return encrypt(key, DEFAULT_IV, plaintext, DEFAULT_MODE, DEFAULT_PADDING);
    }

    /**
     * limoran 按指定参数加密字符串。
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
     * limoran 使用默认参数加密字节数组。
     * @param key 加密密钥
     * @param plaintext 待加密字节数组
     * @return 加密后的字节数组
     * @author limoran
     */
    public static byte[] encryptBytes(String key, byte[] plaintext) {
        return encryptBytes(key, DEFAULT_IV, plaintext, DEFAULT_MODE, DEFAULT_PADDING);
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
     * limoran 使用默认参数解密字符串。
     * @param key 解密密钥
     * @param cipherText Base64编码密文
     * @return 解密后的明文
     * @author limoran
     */
    public static String decrypt(String key, String cipherText) {
        return decrypt(key, DEFAULT_IV, cipherText, DEFAULT_MODE, DEFAULT_PADDING);
    }

    /**
     * limoran 按指定参数解密字符串。
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
     * limoran 使用默认参数解密字节数组。
     * @param key 解密密钥
     * @param cipherBytes 待解密字节数组
     * @return 解密后的字节数组
     * @author limoran
     */
    public static byte[] decryptBytes(String key, byte[] cipherBytes) {
        return decryptBytes(key, DEFAULT_IV, cipherBytes, DEFAULT_MODE, DEFAULT_PADDING);
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
     * @return 目标文件路径，失败返回null
     * @author limoran
     */
    public static Path encryptFile(String key, String sourcePath, String targetPath) {
        return transformFile(Cipher.ENCRYPT_MODE, key, DEFAULT_IV, sourcePath, targetPath, DEFAULT_MODE, DEFAULT_PADDING);
    }

    /**
     * limoran 使用默认参数解密文件。
     * @param key 解密密钥
     * @param sourcePath 源文件路径
     * @param targetPath 目标文件路径
     * @return 目标文件路径，失败返回null
     * @author limoran
     */
    public static Path decryptFile(String key, String sourcePath, String targetPath) {
        return transformFile(Cipher.DECRYPT_MODE, key, DEFAULT_IV, sourcePath, targetPath, DEFAULT_MODE, DEFAULT_PADDING);
    }

    /**
     * limoran 执行文件级转换。
     * @param cipherMode Cipher模式
     * @param key 密钥
     * @param iv 初始化向量
     * @param sourcePath 源文件路径
     * @param targetPath 目标文件路径
     * @param mode 分组模式
     * @param padding 填充方式
     * @return 目标文件路径，失败返回null
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
     * limoran 构建SM4 Cipher实例。
     * @param cipherMode Cipher模式
     * @param key 密钥
     * @param iv 初始化向量
     * @param mode 分组模式
     * @param padding 填充方式
     * @return Cipher实例
     * @author limoran
     */
    private static Cipher buildCipher(int cipherMode, String key, String iv, String mode, String padding) throws GeneralSecurityException {
        ProviderUtil.ensureBouncyCastle();
        String effectiveMode = mode == null || mode.length() == 0 ? DEFAULT_MODE : mode;
        String effectivePadding = padding == null || padding.length() == 0 ? DEFAULT_PADDING : padding;
        String transformation = ALGORITHM + "/" + effectiveMode + "/" + effectivePadding;
        Cipher cipher = Cipher.getInstance(transformation, "BC");
        SecretKeySpec keySpec = new SecretKeySpec(normalizeKey(key), ALGORITHM);
        if ("ECB".equalsIgnoreCase(effectiveMode)) {
            cipher.init(cipherMode, keySpec);
        } else {
            cipher.init(cipherMode, keySpec, new IvParameterSpec(normalizeIv(iv)));
        }
        return cipher;
    }

    /**
     * limoran 规范化SM4密钥长度。
     * @param key 原始密钥
     * @return 规范化后的密钥字节数组
     * @author limoran
     */
    private static byte[] normalizeKey(String key) {
        byte[] bytes = key == null ? new byte[0] : key.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        return Arrays.copyOf(bytes, 16);
    }

    /**
     * limoran 规范化SM4初始化向量长度。
     * @param iv 原始初始化向量
     * @return 规范化后的初始化向量字节数组
     * @author limoran
     */
    private static byte[] normalizeIv(String iv) {
        byte[] bytes = iv == null ? DEFAULT_IV.getBytes(java.nio.charset.StandardCharsets.UTF_8) : iv.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        return Arrays.copyOf(bytes, 16);
    }
}
