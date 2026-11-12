package com.bharath.qr_phishing_detector.detection;

import com.bharath.qr_phishing_detector.validation.URLNormalizationService;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class URLHeuristicsServiceTest {

    private final URLNormalizationService normalizer =
            new URLNormalizationService();

    private final URLHeuristicsService heuristics =
            new URLHeuristicsService();

    @Test
    void ordinaryHttpsUrlHasNoInitialWarnings() {
        String url = "https://example.com";

        var result = heuristics.analyze(
                url, normalizer.normalize(url)
        );

        assertEquals(0, result.score());
        assertTrue(result.reasons().isEmpty());
    }

    @Test
    void detectsUserInformationBeforeHostname() {
        String url = "https://paypal.com@evil.example/login";

        var result = heuristics.analyze(
                url, normalizer.normalize(url)
        );

        assertEquals(30, result.score());
        assertFalse(result.reasons().isEmpty());
    }

    @Test
    void scoresIpAddressHttpAndNonDefaultPort() {
        String url = "http://192.0.2.10:8080/login";

        var result = heuristics.analyze(
                url, normalizer.normalize(url)
        );

        assertEquals(28, result.score());
        assertEquals(3, result.reasons().size());
    }

    @Test
    void scoresDeepHostnameStructure() {
        String url = "https://a.b.c.d.example.com/login";

        var result = heuristics.analyze(
                url, normalizer.normalize(url)
        );

        assertTrue(result.score() >= 8);
    }

    @Test
    void detectsKnownShorteningService() {
        String url = "https://bit.ly/abc123";

        var result = heuristics.analyze(
                url, normalizer.normalize(url)
        );

        assertEquals(12, result.score());
        assertTrue(
                result.reasons().stream()
                        .anyMatch(reason ->
                                reason.contains("URL-shortening service"))
        );
    }

    @Test
    void detectsAnotherKnownShortener() {
        String url = "https://tinyurl.com/demo";

        var result = heuristics.analyze(
                url, normalizer.normalize(url)
        );

        assertEquals(12, result.score());
    }

    @Test
    void doesNotMatchADeceptiveHostnameContainingShortenerText() {
        String url = "https://bit.ly.attacker.test/path";

        var result = heuristics.analyze(
                url, normalizer.normalize(url)
        );

        assertFalse(
                result.reasons().stream()
                        .anyMatch(reason ->
                                reason.contains("URL-shortening service"))
        );
    }
}