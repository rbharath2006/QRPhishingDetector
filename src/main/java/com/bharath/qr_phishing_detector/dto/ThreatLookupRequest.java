package com.bharath.qr_phishing_detector.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ThreatLookupRequest(

        @NotBlank(message = "URL is required.")
        @Size(max = 2048, message = "URL must not exceed 2048 characters.")
        String url

) {
}