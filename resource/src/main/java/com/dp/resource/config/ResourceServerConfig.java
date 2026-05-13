//package com.dp.resource.config;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.oauth2.jwt.JwtDecoder;
//import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
//import org.springframework.security.web.SecurityFilterChain;
//
/// **
// * 资源服务器配置（新版）
// * 使用 RSA 公钥验证 JWT 签名
// */
//@Configuration
//@EnableWebSecurity
//@EnableMethodSecurity
//public class ResourceServerConfig {
//
//    /**
//     * 授权服务器的 JWK 端点地址
//     * 资源服务器从这里获取公钥来验证 JWT
//     */
//    private static final String JWK_SET_URI = "http://localhost:9001/oauth2/jwks";
//
//    @Bean
//    public JwtDecoder jwtDecoder() {
//        // 从授权服务器的 JWK 端点获取公钥
//        return NimbusJwtDecoder.withJwkSetUri(JWK_SET_URI).build();
//    }
//
//    @Bean
//    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//        http
//                .authorizeHttpRequests(authorize -> authorize
//                        .requestMatchers("/api/public/**").permitAll()
//                        .requestMatchers("/api/user/**").hasAnyAuthority("SCOPE_profile", "SCOPE_openid")
//                        .requestMatchers("/api/admin/**").hasAnyAuthority("SCOPE_admin", "ROLE_ADMIN")
//                        .anyRequest().authenticated()
//                )
//                .oauth2ResourceServer(oauth2 -> oauth2
//                        .jwt(jwt -> jwt.decoder(jwtDecoder()))
//                )
//                .csrf(csrf -> csrf.disable());
//
//        return http.build();
//    }
//
//}

package com.dp.resource.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class ResourceServerConfig {

    private static final String JWK_SET_URI = "http://localhost:9001/oauth2/jwks";

    @Bean
    public JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withJwkSetUri(JWK_SET_URI).build();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        // 公开接口 - 不需要认证
                        .requestMatchers("/api/public/**").permitAll()

                        // 用户接口 - 需要 profile 或 openid scope
                        // SCOPE_ 前缀是 OAuth2 scope 的标准写法
                        .requestMatchers("/api/user/**").hasAnyAuthority("SCOPE_profile", "SCOPE_openid")

                        // 管理员接口 - 需要 admin scope 或 ADMIN 角色
                        .requestMatchers("/api/admin/**").hasAnyAuthority("SCOPE_admin", "ROLE_ADMIN")

                        // 其他接口需要认证
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.decoder(jwtDecoder()))
                )
                .csrf(csrf -> csrf.disable());

        return http.build();
    }
}