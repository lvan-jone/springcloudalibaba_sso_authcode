package com.dp.auth.config;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

// 临时运行这个代码生成 gateway-secret 的加密值
public class PasswordGenerator {
    public static void main(String[] args) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String encoded = encoder.encode("gateway-secret");
        System.out.println("gateway-secret 加密结果: " + encoded);
        // 输出示例: $2a$10$xxxxxx...
        //$2a$10$zVGaDIQSnMVChL9HrFg3Te1UOfhIgreXaFnPn5k5oDmuwr4GRIypW
    }
}