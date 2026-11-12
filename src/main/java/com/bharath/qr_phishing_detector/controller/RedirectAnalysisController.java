package com.bharath.qr_phishing_detector.controller;

import com.bharath.qr_phishing_detector.detection.RedirectAnalysisService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/redirect-analysis")
@ConditionalOnProperty(
        prefix = "app.redirect-analysis",
        name = "enabled",
        havingValue = "true"
)
public class RedirectAnalysisController {

    private final RedirectAnalysisService redirectAnalysisService;

    public RedirectAnalysisController(
            RedirectAnalysisService redirectAnalysisService
    ) {
        this.redirectAnalysisService = redirectAnalysisService;
    }

    @PostMapping
    public ResponseEntity<?> analyzeRedirect(
            @RequestBody RedirectAnalysisRequest request
    ) {
        if (request == null
                || request.url() == null
                || request.url().isBlank()
                || request.url().length() > 2048) {

            return ResponseEntity.badRequest().body(
                    Map.of(
                            "error",
                            "Provide a URL between 1 and 2048 characters."
                    )
            );
        }

        try {
            RedirectAnalysisService.Resolution result =
                    redirectAnalysisService.resolve(request.url().trim());

            return ResponseEntity.ok(result);

        } catch (IllegalArgumentException exception) {

            return ResponseEntity.badRequest().body(
                    Map.of("error", "The supplied URL is not eligible for redirect analysis.")
            );

        } catch (InterruptedException exception) {

            Thread.currentThread().interrupt();

            return ResponseEntity.status(HttpStatus.GATEWAY_TIMEOUT).body(
                    Map.of("error", "Redirect analysis was interrupted.")
            );

        } catch (IOException exception) {

            return ResponseEntity.status(HttpStatus.BAD_GATEWAY).body(
                    Map.of("error", "The shortener could not be reached.")
            );
        }
    }

    public record RedirectAnalysisRequest(String url) {
    }
}