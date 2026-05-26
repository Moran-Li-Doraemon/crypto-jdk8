package com.crypto.aesrsa;

import com.crypto.other.Base64Util;
import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;

/**
 * limoran RSA加解密工具类
 * 支持RSA密钥对生成、加解密和签名验签。
 */
public final class RsaUtil {

    private static final String ALGORITHM = "RSA";
    private static final String TRANSFORMATION = "RSA/ECB/PKCS1Padding";

    private RsaUtil() {
    }

    /**
     * limoran 生成默认2048位RSA密钥对。
     * @return 包含公钥和私钥的映射
     * @author limoran
     */
    public static Map<String, String> generateKeyPair() {
        return generateKeyPair(2048);
    }

    /**
     * limoran 按指定长度生成RSA密钥对。
     * @param keySize 密钥长度
     * @return 包含公钥和私钥的映射
     * @author limoran
     */
    public static Map<String, String> generateKeyPair(int keySize) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
            keyPairGenerator.initialize(keySize);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            Map<String, String> keyMap = new HashMap<String, String>(2);
            keyMap.put("publicKey", Base64Util.encode(keyPair.getPublic().getEncoded()));
            keyMap.put("privateKey", Base64Util.encode(keyPair.getPrivate().getEncoded()));
            return keyMap;
        } catch (Throwable throwable) {
            return new HashMap<String, String>(0);
        }
    }

    /**
     * limoran 使用公钥加密字符串。
     * @param publicKey Base64编码的公钥
     * @param plaintext 待加密文本
     * @return Base64编码后的密文
     * @author limoran
     */
    public static String encrypt(String publicKey, String plaintext) {
        if (publicKey == null || plaintext == null) {
            return "";
        }
        try {
            PublicKey key = getPublicKey(publicKey);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] encrypted = processBlocks(cipher, plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8), keySizeBytes(key) - 11);
            return Base64Util.encode(encrypted);
        } catch (Throwable throwable) {
            return "";
        }
    }

    /**
     * limoran 使用私钥解密字符串。
     * @param privateKey Base64编码的私钥
     * @param cipherText Base64编码密文
     * @return 解密后的明文
     * @author limoran
     */
    public static String decrypt(String privateKey, String cipherText) {
        if (privateKey == null || cipherText == null) {
            return "";
        }
        try {
            PrivateKey key = getPrivateKey(privateKey);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] decrypted = processBlocks(cipher, Base64Util.decode(cipherText), keySizeBytes(key));
            return new String(decrypted, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Throwable throwable) {
            return "";
        }
    }

    /**
     * limoran 使用私钥对内容签名。
     * @param privateKey Base64编码的私钥
     * @param content 待签名内容
     * @return Base64编码的签名结果
     * @author limoran
     */
    public static String sign(String privateKey, String content) {
        if (privateKey == null || content == null) {
            return "";
        }
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(getPrivateKey(privateKey));
            signature.update(content.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return Base64Util.encode(signature.sign());
        } catch (Throwable throwable) {
            return "";
        }
    }

    /**
     * limoran 校验RSA签名。
     * @param publicKey Base64编码的公钥
     * @param content 原文内容
     * @param sign Base64编码的签名
     * @return 验证通过返回true，否则返回false
     * @author limoran
     */
    public static boolean verify(String publicKey, String content, String sign) {
        if (publicKey == null || content == null || sign == null) {
            return false;
        }
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(getPublicKey(publicKey));
            signature.update(content.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return signature.verify(Base64Util.decode(sign));
        } catch (Throwable throwable) {
            return false;
        }
    }

    /**
     * limoran 解析RSA公钥。
     * @param publicKey Base64编码的公钥
     * @return 公钥对象
     * @throws Exception 解析失败时抛出异常
     * @author limoran
     */
    public static PublicKey getPublicKey(String publicKey) throws Exception {
        byte[] keyBytes = Base64Util.decode(publicKey);
        return KeyFactory.getInstance(ALGORITHM).generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    /**
     * limoran 解析RSA私钥。
     * @param privateKey Base64编码的私钥
     * @return 私钥对象
     * @throws Exception 解析失败时抛出异常
     * @author limoran
     */
    public static PrivateKey getPrivateKey(String privateKey) throws Exception {
        byte[] keyBytes = Base64Util.decode(privateKey);
        return KeyFactory.getInstance(ALGORITHM).generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }

    /**
     * limoran 计算RSA公钥长度对应的字节数。
     * @param key RSA公钥
     * @return 密钥长度字节数
     * @author limoran
     */
    private static int keySizeBytes(PublicKey key) {
        return ((RSAPublicKey) key).getModulus().bitLength() / 8;
    }

    /**
     * limoran 计算RSA私钥长度对应的字节数。
     * @param key RSA私钥
     * @return 密钥长度字节数
     * @author limoran
     */
    private static int keySizeBytes(PrivateKey key) {
        return ((RSAPrivateKey) key).getModulus().bitLength() / 8;
    }

    /**
     * limoran 按块执行RSA加解密。
     * @param cipher Cipher实例
     * @param input 待处理字节数组
     * @param blockSize 单块大小
     * @return 处理后的字节数组
     * @throws Exception 处理失败时抛出异常
     * @author limoran
     */
    private static byte[] processBlocks(Cipher cipher, byte[] input, int blockSize) throws Exception {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        int offset = 0;
        while (offset < input.length) {
            int length = Math.min(blockSize, input.length - offset);
            outputStream.write(cipher.doFinal(input, offset, length));
            offset += length;
        }
        return outputStream.toByteArray();
    }
}
