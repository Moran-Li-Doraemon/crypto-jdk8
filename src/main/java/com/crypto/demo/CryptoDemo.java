package com.crypto.demo;

import com.crypto.other.HashUtil;
import com.crypto.other.CaesarUtil;

/**
 * limoran 演示入口类
 * 用于快速验证加密工具的基本效果。
 */
public final class CryptoDemo {

    private CryptoDemo() {
    }

    /**
     * limoran 演示入口。
     * @param args 启动参数
     * @return 无
     */
    public static void main(String[] args) {
        System.out.println(HashUtil.md5("hello"));
        System.out.println(CaesarUtil.encrypt("abc123"));
    }
}
