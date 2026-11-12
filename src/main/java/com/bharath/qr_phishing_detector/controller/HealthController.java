package com.bharath.qr_phishing_detector.controller;

import java.time.Instant;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class HealthController {

    @GetMapping("/health")
    public HealthResponse health() {
        return new HealthResponse(
                "UP",
                "QRPhishingDetector",
                "Backend is running successfully",
                Instant.now()
        );
    }

    public record HealthResponse(
            String status,
            String application,
            String message,
            Instant timestamp
    ) {
    }
}