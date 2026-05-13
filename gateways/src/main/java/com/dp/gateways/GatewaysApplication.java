package com.dp.gateways;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@EnableDiscoveryClient
@SpringBootApplication
public class GatewaysApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewaysApplication.class, args);
    }

}
