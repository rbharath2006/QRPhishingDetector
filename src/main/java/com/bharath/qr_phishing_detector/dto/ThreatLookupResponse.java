package com.bharath.qr_phishing_detector.dto;

import java.time.Instant;
import java.util.List;

public record ThreatLookupResponse(
        int riskScore,
        String verdict,
        String evidenceLevel,
        boolean knownThreatMatch,
        String hostname,
        String registrableDomain,
        Instant checkedAt,
        List<ThreatMatch> matches,
        List<String> explanations
) {

    public record ThreatMatch(
            String indicatorType,
            String threatType,
            String sourceName,
            Integer sourceConfidence,
            Instant sourceUpdatedAt,
            Instant lastSeenAt
    ) {
    }
}