package com.bharath.qr_phishing_detector.controller;

import com.bharath.qr_phishing_detector.dto.ThreatLookupRequest;
import com.bharath.qr_phishing_detector.dto.ThreatLookupResponse;
import com.bharath.qr_phishing_detector.service.ThreatLookupService;

import jakarta.validation.Valid;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/intelligence")
public class ThreatLookupController {

    private final ThreatLookupService threatLookupService;

    public ThreatLookupController(
            ThreatLookupService threatLookupService
    ) {
        this.threatLookupService = threatLookupService;
    }

    @PostMapping("/lookup")
    public ThreatLookupResponse lookup(
            @Valid @RequestBody ThreatLookupRequest request
    ) {
        return threatLookupService.lookup(request.url());
    }
}