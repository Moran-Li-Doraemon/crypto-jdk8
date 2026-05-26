package com.crypto.gm;

import com.crypto.other.Base64Util;
import com.crypto.other.HexUtil;
import com.crypto.other.ProviderUtil;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Strings;

/**
 * limoran SM2工具类
 * 支持SM2密钥对生成、加解密和签名验签。
 */
public final class Sm2Util {

    private static final String CURVE_NAME = "sm2p256v1";
    private static final String DEFAULT_USER_ID = "1234567812345678";

    private Sm2Util() {
    }

    /**
     * limoran 生成SM2密钥对。
     * @return 包含公钥和私钥的映射
     * @author limoran
     */
    public static Map<String, String> generateKeyPair() {
        ProviderUtil.ensureBouncyCastle();
        X9ECParameters parameters = GMNamedCurves.getByName(CURVE_NAME);
        ECDomainParameters domainParameters = new ECDomainParameters(parameters.getCurve(), parameters.getG(), parameters.getN(), parameters.getH());
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(new ECKeyGenerationParameters(domainParameters, new SecureRandom()));
        AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
        ECPoint publicPoint = ((ECPublicKeyParameters) keyPair.getPublic()).getQ();
        BigInteger privateKey = ((ECPrivateKeyParameters) keyPair.getPrivate()).getD();
        Map<String, String> result = new HashMap<String, String>(2);
        result.put("publicKey", HexUtil.toHex(publicPoint.getEncoded(false)));
        result.put("privateKey", privateKey.toString(16));
        return result;
    }

    /**
     * limoran 使用默认模式加密字符串。
     * @param publicKey 十六进制公钥
     * @param plaintext 待加密文本
     * @return 十六进制密文
     * @author limoran
     */
    public static String encrypt(String publicKey, String plaintext) {
        return encrypt(publicKey, plaintext, "C1C3C2");
    }

    /**
     * limoran 使用指定模式加密字符串。
     * @param publicKey 十六进制公钥
     * @param plaintext 待加密文本
     * @param modeName SM2输出模式
     * @return 十六进制密文
     * @author limoran
     */
    public static String encrypt(String publicKey, String plaintext, String modeName) {
        if (publicKey == null || plaintext == null) {
            return "";
        }
        try {
            ProviderUtil.ensureBouncyCastle();
            X9ECParameters parameters = GMNamedCurves.getByName(CURVE_NAME);
            ECDomainParameters domainParameters = new ECDomainParameters(parameters.getCurve(), parameters.getG(), parameters.getN(), parameters.getH());
            ECPoint publicPoint = parameters.getCurve().decodePoint(HexUtil.fromHex(publicKey));
            ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(publicPoint, domainParameters);
            SM2Engine engine = new SM2Engine(toMode(modeName));
            engine.init(true, new ParametersWithRandom(publicKeyParameters, new SecureRandom()));
            byte[] cipherBytes = engine.processBlock(plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8), 0, plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
            return HexUtil.toHex(cipherBytes);
        } catch (Throwable throwable) {
            return "";
        }
    }

    /**
     * limoran 使用默认模式解密字符串。
     * @param privateKey 十六进制私钥
     * @param cipherText 十六进制密文
     * @return 解密后的明文
     * @author limoran
     */
    public static String decrypt(String privateKey, String cipherText) {
        return decrypt(privateKey, cipherText, "C1C3C2");
    }

    /**
     * limoran 使用指定模式解密字符串。
     * @param privateKey 十六进制私钥
     * @param cipherText 十六进制密文
     * @param modeName SM2输出模式
     * @return 解密后的明文
     * @author limoran
     */
    public static String decrypt(String privateKey, String cipherText, String modeName) {
        if (privateKey == null || cipherText == null) {
            return "";
        }
        try {
            ProviderUtil.ensureBouncyCastle();
            X9ECParameters parameters = GMNamedCurves.getByName(CURVE_NAME);
            ECDomainParameters domainParameters = new ECDomainParameters(parameters.getCurve(), parameters.getG(), parameters.getN(), parameters.getH());
            ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(new BigInteger(privateKey, 16), domainParameters);
            SM2Engine engine = new SM2Engine(toMode(modeName));
            engine.init(false, privateKeyParameters);
            byte[] plainBytes = engine.processBlock(HexUtil.fromHex(cipherText), 0, HexUtil.fromHex(cipherText).length);
            return new String(plainBytes, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Throwable throwable) {
            return "";
        }
    }

    /**
     * limoran 使用默认用户标识签名。
     * @param privateKey 十六进制私钥
     * @param content 待签名内容
     * @return 十六进制签名结果
     * @author limoran
     */
    public static String sign(String privateKey, String content) {
        return sign(privateKey, content, DEFAULT_USER_ID);
    }

    /**
     * limoran 按指定用户标识签名。
     * @param privateKey 十六进制私钥
     * @param content 待签名内容
     * @param userId 用户标识
     * @return 十六进制签名结果
     * @author limoran
     */
    public static String sign(String privateKey, String content, String userId) {
        if (privateKey == null || content == null) {
            return "";
        }
        try {
            ProviderUtil.ensureBouncyCastle();
            X9ECParameters parameters = GMNamedCurves.getByName(CURVE_NAME);
            ECDomainParameters domainParameters = new ECDomainParameters(parameters.getCurve(), parameters.getG(), parameters.getN(), parameters.getH());
            ECPrivateKeyParameters privateKeyParameters = new ECPrivateKeyParameters(new BigInteger(privateKey, 16), domainParameters);
            SM2Signer signer = new SM2Signer();
            ParametersWithRandom parametersWithRandom = new ParametersWithRandom(privateKeyParameters, new SecureRandom());
            ParametersWithID parametersWithID = new ParametersWithID(parametersWithRandom, Strings.toByteArray(normalizeUserId(userId)));
            signer.init(true, parametersWithID);
            byte[] contentBytes = content.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            signer.update(contentBytes, 0, contentBytes.length);
            return HexUtil.toHex(signer.generateSignature());
        } catch (Throwable throwable) {
            return "";
        }
    }

    /**
     * limoran 使用默认用户标识验签。
     * @param publicKey 十六进制公钥
     * @param content 原文内容
     * @param sign 十六进制签名
     * @return 验证通过返回true，否则返回false
     * @author limoran
     */
    public static boolean verify(String publicKey, String content, String sign) {
        return verify(publicKey, content, sign, DEFAULT_USER_ID);
    }

    /**
     * limoran 按指定用户标识验签。
     * @param publicKey 十六进制公钥
     * @param content 原文内容
     * @param sign 十六进制签名
     * @param userId 用户标识
     * @return 验证通过返回true，否则返回false
     * @author limoran
     */
    public static boolean verify(String publicKey, String content, String sign, String userId) {
        if (publicKey == null || content == null || sign == null) {
            return false;
        }
        try {
            ProviderUtil.ensureBouncyCastle();
            X9ECParameters parameters = GMNamedCurves.getByName(CURVE_NAME);
            ECDomainParameters domainParameters = new ECDomainParameters(parameters.getCurve(), parameters.getG(), parameters.getN(), parameters.getH());
            ECPoint publicPoint = parameters.getCurve().decodePoint(HexUtil.fromHex(publicKey));
            ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(publicPoint, domainParameters);
            SM2Signer signer = new SM2Signer();
            ParametersWithID parametersWithID = new ParametersWithID(publicKeyParameters, Strings.toByteArray(normalizeUserId(userId)));
            signer.init(false, parametersWithID);
            byte[] contentBytes = content.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            signer.update(contentBytes, 0, contentBytes.length);
            return signer.verifySignature(HexUtil.fromHex(sign));
        } catch (Throwable throwable) {
            return false;
        }
    }

    /**
     * limoran 将模式名称转换为SM2模式枚举。
     * @param modeName 模式名称
     * @return SM2模式枚举
     * @author limoran
     */
    private static SM2Engine.Mode toMode(String modeName) {
        if ("C1C2C3".equalsIgnoreCase(modeName)) {
            return SM2Engine.Mode.C1C2C3;
        }
        return SM2Engine.Mode.C1C3C2;
    }

    /**
     * limoran 规范化用户标识。
     * @param userId 用户标识
     * @return 规范化后的用户标识
     * @author limoran
     */
    private static String normalizeUserId(String userId) {
        if (userId == null || userId.length() == 0) {
            return DEFAULT_USER_ID;
        }
        return userId;
    }
}
