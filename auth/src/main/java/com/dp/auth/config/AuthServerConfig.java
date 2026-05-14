package com.dp.auth.config;

import com.dp.auth.service.CustomUserDetailsService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.sql.DataSource;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * 认证服务器配置（新版 Spring Authorization Server）
 */
@Slf4j
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
        log.info("【2.Bean初始化】passwordEncoder - 密码编码器创建（支持bcrypt和noop）");
        // 创建支持多种编码方式的密码编码器
        String defaultEncoding = "bcrypt";
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put("bcrypt", new BCryptPasswordEncoder());
        encoders.put("noop", NoOpPasswordEncoder.getInstance());
        DelegatingPasswordEncoder delegatingPasswordEncoder = new DelegatingPasswordEncoder(defaultEncoding, encoders);
        delegatingPasswordEncoder.setDefaultPasswordEncoderForMatches(new BCryptPasswordEncoder());
        log.info("密码编码器配置完成 - 默认使用BCrypt算法");
        return delegatingPasswordEncoder;
    }


    @Bean
    public UserDetailsService userDetailsService() {
        log.info("【3.Bean初始化】userDetailsService - 用户详情服务创建（使用CustomUserDetailsService）");
        return customUserDetailsService;
    }
    // ==================== 2. OAuth2 客户端配置（替代 AuthorizationServerConfig） ====================

    /**
     * 创建 JdbcTemplate 用于数据库操作
     * ==================== 1. 数据基础设施 ====================
     */
    @Bean
    public JdbcOperations jdbcOperations() {
        log.info("【1.Bean初始化】jdbcOperations - JDBC操作模板创建");
        return new JdbcTemplate(dataSource);
    }

    /**
     * 客户端注册信息仓库
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcOperations jdbcOperations) {
        log.info("【Bean初始化】registeredClientRepository - 客户端仓库创建");
        JdbcRegisteredClientRepository repository = new JdbcRegisteredClientRepository(jdbcOperations);
        // 检查是否已存在客户端，如果不存在则初始化默认客户端
        if (repository.findByClientId("gateway-client") == null) {
            // 创建默认客户端（实际生产环境应该通过 SQL 初始化）
            // 这里保留代码逻辑作为备选，但推荐使用 SQL 脚本初始化
        }
        return repository;
    }

    // ==================== 3. JWT 配置（替代 JwtAccessTokenConverter） ====================

    /**
     * OAuth2 授权记录服务（存储到 MySQL）
     */
    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcOperations jdbcOperations,
                                                           RegisteredClientRepository registeredClientRepository) {
        log.info("【Bean初始化】authorizationService - OAuth2授权记录服务创建（存储到MySQL）");
        log.info("  作用：存储授权码、Access Token、Refresh Token到数据库");
        log.info("  表名：oauth2_authorization");
        return new JdbcOAuth2AuthorizationService(jdbcOperations, registeredClientRepository);
    }

    /**
     * OAuth2 授权确认服务（存储到 MySQL）
     */
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcOperations jdbcOperations,
                                                                         RegisteredClientRepository registeredClientRepository) {
        log.info("【Bean初始化】authorizationConsentService - OAuth2授权确认服务创建（存储到MySQL）");
        log.info("  作用：记录用户同意授权的权限范围");
        log.info("  表名：oauth2_authorization_consent");
        return new JdbcOAuth2AuthorizationConsentService(jdbcOperations, registeredClientRepository);
    }

    /**
     * JWT 密钥源 - 生成 RSA 密钥对
     * 替代旧版的 JwtAccessTokenConverter
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        log.info("【Bean初始化】jwkSource - JWT密钥源创建");
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        log.info("【JWK配置】密钥: {}", rsaKey);
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * 生成 RSA 密钥对
     * 用于 JWT 签名和验证
     */
    private static KeyPair generateRsaKey() {
        try {
            log.info("【RSA密钥生成】开始生成2048位RSA密钥对");
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
        log.info("【Bean初始化】authorizationServerSecurityFilterChain - OAuth2授权服务器安全配置（@Order(1)，最高优先级）");
        log.info("  保护的端点：/oauth2/authorize, /oauth2/token, /oauth2/jwks, /userinfo");
        log.info("  请求匹配：所有OAuth2相关的端点");
        // 应用默认的 OAuth2 授权服务器配置
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        // 启用 OIDC 协议
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());
        log.info("  ✅ OIDC协议已启用");
        log.info("  ✅ 表单登录已启用");
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
        log.info("【Bean初始化】defaultSecurityFilterChain - 默认安全配置（@Order(2)，次优先级）");
        log.info("  保护的端点：/login, /logout, 所有其他端点（除了/.well-known/**）");
        log.info("  作用：提供登录页面、处理登录请求、会话管理");
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
        log.info("【Bean初始化】authorizationServerSettings - 授权服务器端点配置");
        log.info("  Issuer URI: http://localhost:9001");
        log.info("  授权端点: /oauth2/authorize");
        log.info("  Token端点: /oauth2/token");
        log.info("  JWK端点: /oauth2/jwks");
        log.info("  用户信息端点: /userinfo");
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:9001")                    // 服务签发者
                .authorizationEndpoint("/oauth2/authorize")         // 授权端点（对应旧版的 /oauth/authorize）
                .tokenEndpoint("/oauth2/token")                     // Token 端点（对应旧版的 /oauth/token）
                .jwkSetEndpoint("/oauth2/jwks")                     // JWK 端点
                .oidcUserInfoEndpoint("/userinfo")                  // 用户信息端点
                .build();
    }

}