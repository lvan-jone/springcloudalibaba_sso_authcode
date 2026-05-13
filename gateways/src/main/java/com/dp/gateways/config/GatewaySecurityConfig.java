package com.dp.gateways.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.logout.RedirectServerLogoutSuccessHandler;

import java.net.URI;

@Configuration
@EnableWebFluxSecurity
public class GatewaySecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        // 登录成功处理器
        RedirectServerAuthenticationSuccessHandler loginSuccessHandler =
                new RedirectServerAuthenticationSuccessHandler("/");

        // 退出成功处理器
        RedirectServerLogoutSuccessHandler logoutSuccessHandler =
                new RedirectServerLogoutSuccessHandler();
        logoutSuccessHandler.setLogoutSuccessUrl(URI.create("/login?logout"));

        return http
                .csrf(csrf -> csrf.disable())
                .authorizeExchange(exchange -> exchange
                        .pathMatchers("/", "/login", "/logout", "/favicon.ico").permitAll()
                        .anyExchange().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .authenticationSuccessHandler(loginSuccessHandler)
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessHandler(logoutSuccessHandler)
                )
                .build();
    }
}