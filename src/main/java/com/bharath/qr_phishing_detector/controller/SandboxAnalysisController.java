package com.bharath.qr_phishing_detector.controller;

import java.net.URI;
import java.util.Map;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

@RestController
@RequestMapping("/api/v1/sandbox-analysis")
@ConditionalOnProperty(prefix = "app.sandbox", name = "enabled", havingValue = "true")
public class SandboxAnalysisController {

    private final RestClient sandboxWorkerRestClient;

    public SandboxAnalysisController(RestClient sandboxWorkerRestClient) {
        this.sandboxWorkerRestClient = sandboxWorkerRestClient;
    }

    @PostMapping
    public ResponseEntity<?> analyze(@RequestBody SandboxRequest request) {
        if (request == null || request.url() == null || request.url().isBlank()
                || request.url().length() > 2048) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Provide a URL between 1 and 2048 characters."));
        }

        final URI uri;
        try {
            uri = URI.create(request.url().trim());
        } catch (IllegalArgumentException exception) {
            return ResponseEntity.badRequest().body(Map.of("error", "The supplied URL is invalid."));
        }
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null
                || uri.getUserInfo() != null
                || (uri.getPort() != -1 && uri.getPort() != 443)) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Sandbox analysis accepts valid HTTPS URLs on the standard port only."));
        }

        try {
            Map<?, ?> result = sandboxWorkerRestClient.post()
                    .uri("/analyze")
                    .body(Map.of("url", request.url().trim()))
                    .retrieve()
                    .body(Map.class);
            return ResponseEntity.ok(result == null ? Map.of("error", "Sandbox returned no result.") : result);
        } catch (RestClientResponseException exception) {
            int upstreamStatus = exception.getStatusCode().value();
            if (upstreamStatus == 400 || upstreamStatus == 429) {
                return ResponseEntity.status(upstreamStatus).body(Map.of(
                        "error", upstreamStatus == 429
                                ? "Sandbox is busy. Try again shortly."
                                : "The sandbox rejected the URL or request."));
            }
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(Map.of(
                    "error", "Sandbox analysis could not be completed."));
        } catch (ResourceAccessException exception) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of(
                    "error", "The sandbox worker is not reachable or timed out."));
        }
    }

    public record SandboxRequest(String url) { }
}
