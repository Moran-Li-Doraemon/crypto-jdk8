package com.crypto.other;

import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * limoran BouncyCastle提供者工具类
 * 用于在运行时安全注册BC provider。
 */
public final class ProviderUtil {

    private static volatile boolean loaded;

    private ProviderUtil() {
    }

    /**
     * limoran 确保BouncyCastle已注册到JCA提供者列表。
     * @return 无
     */
    public static void ensureBouncyCastle() {
        if (loaded) {
            return;
        }
        synchronized (ProviderUtil.class) {
            if (loaded) {
                return;
            }
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
            loaded = true;
        }
    }
}
