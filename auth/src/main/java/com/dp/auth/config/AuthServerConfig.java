package com.dp.auth.config;

import com.dp.auth.service.CustomUserDetailsService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * 认证服务器配置（新版 Spring Authorization Server）
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class AuthServerConfig {
    private final DataSource dataSource;
    private final CustomUserDetailsService customUserDetailsService;


    // ==================== 1. 用户认证配置（保持不变） ====================

    /**
     * 密码编码器. 使用 BCrypt 加密，存储时自动加盐
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        // 创建支持多种编码方式的密码编码器
        String defaultEncoding = "bcrypt";
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put("bcrypt", new BCryptPasswordEncoder());
        encoders.put("noop", NoOpPasswordEncoder.getInstance());
        DelegatingPasswordEncoder delegatingPasswordEncoder = new DelegatingPasswordEncoder(defaultEncoding, encoders);
        delegatingPasswordEncoder.setDefaultPasswordEncoderForMatches(new BCryptPasswordEncoder());
        return delegatingPasswordEncoder;
    }

    /**
     * 用户详情服务
     * 定义测试用户：admin/123456, user/123456
     * 密码使用 BCrypt 加密
     */
//    @Bean
//    public UserDetailsService userDetailsService() {
//        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
//
//        // 密码: 123456 的 BCrypt 加密结果
//        UserDetails admin = User.withUsername("admin")
//                .password("$2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iAt6Z5EHsM8lE9lBOsl7iKTVKIUi")
//                .roles("ADMIN", "USER")
//                .build();
//
//        UserDetails user = User.withUsername("user")
//                .password("$2a$10$N.zmdr9k7uOCQb376NoUnuTJ8iAt6Z5EHsM8lE9lBOsl7iKTVKIUi")
//                .roles("USER")
//                .build();
//
//        manager.createUser(admin);
//        manager.createUser(user);
//        return manager;
//    }
    @Bean
    public UserDetailsService userDetailsService() {
        return customUserDetailsService;
    }
    // ==================== 2. OAuth2 客户端配置（替代 AuthorizationServerConfig） ====================

    /**
     * 创建 JdbcTemplate 用于数据库操作
     */
    @Bean
    public JdbcOperations jdbcOperations() {
        return new JdbcTemplate(dataSource);
    }

    /**
     * 客户端注册信息仓库
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcOperations jdbcOperations) {
        JdbcRegisteredClientRepository repository = new JdbcRegisteredClientRepository(jdbcOperations);

        // 检查是否已存在客户端，如果不存在则初始化默认客户端
        if (repository.findByClientId("gateway-client") == null) {
            // 创建默认客户端（实际生产环境应该通过 SQL 初始化）
            // 这里保留代码逻辑作为备选，但推荐使用 SQL 脚本初始化
        }
        return repository;
    }
//    @Bean
//    public RegisteredClientRepository registeredClientRepository() {
//        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
//        RegisteredClient gatewayClient = RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId("gateway-client")
//                .clientSecret(encoder.encode("gateway-secret"))
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                // 添加密码授权类型
//                .authorizationGrantType(AuthorizationGrantType.PASSWORD)  // 新增
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                .redirectUri("https://oauth.pstmn.io/v1/callback")
//                // 添加 admin scope
//                .scope("openid")
//                .scope("profile")
//                .scope("admin")  // 新增 admin scope
//                .clientSettings(ClientSettings.builder()
//                        .requireAuthorizationConsent(false)
//                        .build())
//                .tokenSettings(TokenSettings.builder()
//                        .accessTokenTimeToLive(Duration.ofHours(1))
//                        .refreshTokenTimeToLive(Duration.ofDays(7))
//                        .build())
//                .build();
//
//        return new InMemoryRegisteredClientRepository(gatewayClient);
//    }

    // ==================== 3. JWT 配置（替代 JwtAccessTokenConverter） ====================

    /**
     * OAuth2 授权记录服务（存储到 MySQL）
     */
    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcOperations jdbcOperations,
                                                           RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
    }

    /**
     * OAuth2 授权确认服务（存储到 MySQL）
     */
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcOperations jdbcOperations,
                                                                         RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcOperations, registeredClientRepository);
    }

    /**
     * JWT 密钥源 - 生成 RSA 密钥对
     * 替代旧版的 JwtAccessTokenConverter
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * 生成 RSA 密钥对
     * 用于 JWT 签名和验证
     */
    private static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    /**
     * JWT 解码器
     * 用于验证 Token
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * Token 存储（新版使用 JwtDecoder，不需要单独的 TokenStore）
     * 注意：新版不需要 TokenStore Bean，JwtDecoder 已经处理
     */

    // ==================== 4. 安全过滤器链配置（替代 WebSecurityConfigurerAdapter） ====================

    /**
     * OAuth2 授权服务器安全配置（优先级最高）
     * 替代旧版的 AuthorizationServerSecurityConfigurer
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // 应用默认的 OAuth2 授权服务器配置
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        // 启用 OIDC 协议
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());
        // 启用表单登录（替代旧版的 allowFormAuthenticationForClients）
        return http.formLogin(Customizer.withDefaults()).build();
    }

    /**
     * 默认安全配置（优先级次之）
     * 替代旧版的 SecurityConfig 内部类
     * 对应旧版的 configure(HttpSecurity http) 方法
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        RequestCache requestCache = new HttpSessionRequestCache();

        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/.well-known/**", "/favicon.ico", "/error").permitAll()
                        .anyRequest().authenticated()
                )
                .userDetailsService(customUserDetailsService)
                // 不指定 loginPage，使用 Spring Security 默认的登录页面
                .formLogin(form -> form
                        .successHandler((request, response, authentication) -> {
                            SavedRequest savedRequest = (SavedRequest) request.getSession()
                                    .getAttribute("SPRING_SECURITY_SAVED_REQUEST");

                            if (savedRequest != null) {
                                String targetUrl = savedRequest.getRedirectUrl();
                                response.sendRedirect(targetUrl);
                            } else {
                                response.sendRedirect("/");
                            }
                        })
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutSuccessUrl("/login?logout")
                        .permitAll()
                )
                .requestCache(cache -> cache.requestCache(requestCache));

        return http.build();
    }

    /**
     * 授权服务器设置
     * 配置授权服务器的基础 URL 和端点
     */
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:9001")                    // 服务签发者
                .authorizationEndpoint("/oauth2/authorize")         // 授权端点（对应旧版的 /oauth/authorize）
                .tokenEndpoint("/oauth2/token")                     // Token 端点（对应旧版的 /oauth/token）
                .jwkSetEndpoint("/oauth2/jwks")                     // JWK 端点
                .oidcUserInfoEndpoint("/userinfo")                  // 用户信息端点
                .build();
    }
}