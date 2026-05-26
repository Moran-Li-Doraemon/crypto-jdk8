package com.crypto.demo;

import com.crypto.aesrsa.AesUtil;
import com.crypto.aesrsa.RsaUtil;
import com.crypto.gm.Sm2Util;
import com.crypto.gm.Sm3Util;
import com.crypto.gm.Sm4Util;
import com.crypto.other.CaesarUtil;
import com.crypto.other.HashUtil;
import com.crypto.other.SkaUtil;
import com.crypto.other.SubmergeUtil;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * limoran 加密工具烟雾测试
 * 用于验证核心算法的基础往返能力。
 */
public class CryptoSmokeTest {

    /**
     * limoran 验证AES加解密往返。
     * @return 无
     */
    @Test
    public void aesRoundTrip() {
        String key = AesUtil.generateKey();
        String cipher = AesUtil.encrypt(key, "hello-aes");
        Assertions.assertEquals("hello-aes", AesUtil.decrypt(key, cipher));
    }

    /**
     * limoran 验证RSA加解密往返。
     * @return 无
     */
    @Test
    public void rsaRoundTrip() {
        Map<String, String> keyPair = RsaUtil.generateKeyPair(2048);
        String cipher = RsaUtil.encrypt(keyPair.get("publicKey"), "hello-rsa");
        Assertions.assertEquals("hello-rsa", RsaUtil.decrypt(keyPair.get("privateKey"), cipher));
    }

    /**
     * limoran 验证SM2加解密和签名验签。
     * @return 无
     */
    @Test
    public void sm2RoundTrip() {
        Map<String, String> keyPair = Sm2Util.generateKeyPair();
        String cipher = Sm2Util.encrypt(keyPair.get("publicKey"), "hello-sm2");
        Assertions.assertEquals("hello-sm2", Sm2Util.decrypt(keyPair.get("privateKey"), cipher));
        String sign = Sm2Util.sign(keyPair.get("privateKey"), "hello-sm2");
        Assertions.assertTrue(Sm2Util.verify(keyPair.get("publicKey"), "hello-sm2", sign));
    }

    /**
     * limoran 验证SM4加解密往返。
     * @return 无
     */
    @Test
    public void sm4RoundTrip() {
        String key = Sm4Util.generateKey();
        String cipher = Sm4Util.encrypt(key, "hello-sm4");
        Assertions.assertEquals("hello-sm4", Sm4Util.decrypt(key, cipher));
    }

    /**
     * limoran 验证哈希与混淆工具。
     * @return 无
     */
    @Test
    public void hashAndObfuscation() throws Exception {
        Assertions.assertEquals(32, HashUtil.md5("hello").length());
        Assertions.assertEquals(64, HashUtil.sha256("hello").length());
        Assertions.assertEquals(64, Sm3Util.hash("hello").length());
        Assertions.assertEquals("abc123", CaesarUtil.decrypt(CaesarUtil.encrypt("abc123")));
        Assertions.assertEquals("abc123", SkaUtil.decrypt(SkaUtil.encrypt("abc123")));
        String key = SubmergeUtil.generateKey(128);
        String cipher = SubmergeUtil.encrypt(key, "hello-submerge");
        Assertions.assertEquals("hello-submerge", SubmergeUtil.decrypt(key, cipher));
        Path tempFile = Files.createTempFile("crypto", ".txt");
        Files.write(tempFile, "hello-file".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        Assertions.assertEquals(64, HashUtil.sm3(tempFile.toString()).length());
        Files.deleteIfExists(tempFile);
    }
}
