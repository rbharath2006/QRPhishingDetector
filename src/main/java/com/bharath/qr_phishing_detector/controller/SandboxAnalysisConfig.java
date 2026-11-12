package com.bharath.qr_phishing_detector.controller;

import java.net.http.HttpClient;
import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

@Configuration
@ConditionalOnProperty(prefix = "app.sandbox", name = "enabled", havingValue = "true")
public class SandboxAnalysisConfig {

    @Bean
    RestClient sandboxWorkerRestClient(@Value("${app.sandbox.gateway-url:http://127.0.0.1:8765}") String gatewayUrl) {
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .build();
        JdkClientHttpRequestFactory requestFactory = new JdkClientHttpRequestFactory(client);
        requestFactory.setReadTimeout(Duration.ofSeconds(40));
        return RestClient.builder()
                .baseUrl(gatewayUrl)
                .requestFactory(requestFactory)
                .build();
    }
}
