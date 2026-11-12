package com.bharath.qr_phishing_detector.validation;

import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.*;

class URLNormalizationServiceTest {

    private final URLNormalizationService normalizer =
            new URLNormalizationService();

    @Test
    void normalizesSchemeHostDefaultPortAndFragment() {
        var result = normalizer.normalize(
                "HTTPS://Example.com:443/account#section"
        );

        assertEquals("https://example.com/account",
                result.canonicalUrl());
        assertEquals("example.com", result.hostname());
    }

    @Test
    void extractsActualHostnameFromUserInformationUrl() {
        var result = normalizer.normalize(
                "https://paypal.com@evil.example/login"
        );

        assertEquals("evil.example", result.hostname());
    }

    @Test
    void rejectsUnsupportedSchemes() {
        assertThrows(
                ResponseStatusException.class,
                () -> normalizer.normalize("javascript:alert(1)")
        );
    }

    @Test
    void rejectsBlankInput() {
        assertThrows(
                ResponseStatusException.class,
                () -> normalizer.normalize(" ")
        );
    }

    @Test
    void rejectsExcessivelyLongInput() {
        String longInput = "https://example.com/" + "a".repeat(2100);

        assertThrows(
                ResponseStatusException.class,
                () -> normalizer.normalize(longInput)
        );
    }
}