package com.crypto.other;

import com.crypto.other.HexUtil;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.crypto.digests.SM3Digest;

/**
 * limoran 摘要算法工具类
 * 封装MD5、SHA和SM3的字符串与文件摘要计算。
 */
public final class DigestUtil {

    private DigestUtil() {
    }

    /**
     * limoran 计算字符串的MD5摘要。
     * @param text 待计算的文本
     * @return MD5摘要的十六进制字符串
     * @author limoran
     */
    public static String md5(String text) {
        return digest("MD5", text == null ? new byte[0] : text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * limoran 计算字节数组的MD5摘要。
     * @param bytes 待计算的字节数组
     * @return MD5摘要的十六进制字符串
     * @author limoran
     */
    public static String md5(byte[] bytes) {
        return digest("MD5", bytes);
    }

    /**
     * limoran 计算文件的MD5摘要。
     * @param path 文件路径
     * @return MD5摘要的十六进制字符串
     * @author limoran
     */
    public static String md5File(String path) {
        return digestFile("MD5", path);
    }

    /**
     * limoran 计算字符串的SHA-1摘要。
     * @param text 待计算的文本
     * @return SHA-1摘要的十六进制字符串
     * @author limoran
     */
    public static String sha1(String text) {
        return digest("SHA-1", text == null ? new byte[0] : text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * limoran 计算字符串的SHA-256摘要。
     * @param text 待计算的文本
     * @return SHA-256摘要的十六进制字符串
     * @author limoran
     */
    public static String sha256(String text) {
        return digest("SHA-256", text == null ? new byte[0] : text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * limoran 计算字符串的SHA-384摘要。
     * @param text 待计算的文本
     * @return SHA-384摘要的十六进制字符串
     * @author limoran
     */
    public static String sha384(String text) {
        return digest("SHA-384", text == null ? new byte[0] : text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * limoran 计算字符串的SHA-512摘要。
     * @param text 待计算的文本
     * @return SHA-512摘要的十六进制字符串
     * @author limoran
     */
    public static String sha512(String text) {
        return digest("SHA-512", text == null ? new byte[0] : text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * limoran 计算文件的SHA-1摘要。
     * @param path 文件路径
     * @return SHA-1摘要的十六进制字符串
     * @author limoran
     */
    public static String sha1File(String path) {
        return digestFile("SHA-1", path);
    }

    /**
     * limoran 计算文件的SHA-256摘要。
     * @param path 文件路径
     * @return SHA-256摘要的十六进制字符串
     * @author limoran
     */
    public static String sha256File(String path) {
        return digestFile("SHA-256", path);
    }

    /**
     * limoran 计算文件的SHA-384摘要。
     * @param path 文件路径
     * @return SHA-384摘要的十六进制字符串
     * @author limoran
     */
    public static String sha384File(String path) {
        return digestFile("SHA-384", path);
    }

    /**
     * limoran 计算文件的SHA-512摘要。
     * @param path 文件路径
     * @return SHA-512摘要的十六进制字符串
     * @author limoran
     */
    public static String sha512File(String path) {
        return digestFile("SHA-512", path);
    }

    /**
     * limoran 计算字符串的SM3摘要。
     * @param text 待计算的文本
     * @return SM3摘要的十六进制字符串
     * @author limoran
     */
    public static String sm3(String text) {
        return sm3(text == null ? new byte[0] : text.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    /**
     * limoran 计算字节数组的SM3摘要。
     * @param bytes 待计算的字节数组
     * @return SM3摘要的十六进制字符串
     * @author limoran
     */
    public static String sm3(byte[] bytes) {
        ProviderUtil.ensureBouncyCastle();
        if (bytes == null) {
            return "";
        }
        SM3Digest digest = new SM3Digest();
        digest.update(bytes, 0, bytes.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return HexUtil.toHex(hash);
    }

    /**
     * limoran 计算文件的SM3摘要。
     * @param path 文件路径
     * @return SM3摘要的十六进制字符串
     * @author limoran
     */
    public static String sm3File(String path) {
        if (path == null || path.length() == 0) {
            return "";
        }
        ProviderUtil.ensureBouncyCastle();
        try (InputStream inputStream = Files.newInputStream(Paths.get(path))) {
            SM3Digest digest = new SM3Digest();
            byte[] buffer = new byte[8192];
            int read;
            while ((read = inputStream.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
            byte[] hash = new byte[digest.getDigestSize()];
            digest.doFinal(hash, 0);
            return HexUtil.toHex(hash);
        } catch (IOException e) {
            return "";
        }
    }

    /**
     * limoran 按指定算法计算字节数组摘要。
     * @param algorithm 摘要算法名称
     * @param bytes 待计算的字节数组
     * @return 摘要的十六进制字符串
     * @author limoran
     */
    public static String digest(String algorithm, byte[] bytes) {
        if (bytes == null) {
            return "";
        }
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
            return HexUtil.toHex(messageDigest.digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            return "";
        }
    }

    /**
     * limoran 按指定算法计算文件摘要。
     * @param algorithm 摘要算法名称
     * @param path 文件路径
     * @return 摘要的十六进制字符串
     * @author limoran
     */
    public static String digestFile(String algorithm, String path) {
        if (path == null || path.length() == 0) {
            return "";
        }
        try (InputStream inputStream = Files.newInputStream(Paths.get(path))) {
            MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
            byte[] buffer = new byte[8192];
            int read;
            while ((read = inputStream.read(buffer)) != -1) {
                messageDigest.update(buffer, 0, read);
            }
            return HexUtil.toHex(messageDigest.digest());
        } catch (IOException | NoSuchAlgorithmException e) {
            return "";
        }
    }
}
