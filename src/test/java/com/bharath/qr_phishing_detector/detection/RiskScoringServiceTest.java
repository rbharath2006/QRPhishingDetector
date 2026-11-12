package com.bharath.qr_phishing_detector.detection;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RiskScoringServiceTest {

    private final RiskScoringService scoring =
            new RiskScoringService();

    @Test
    void knownThreatMatchReceivesPriority() {
        var result = scoring.assess(true, 0);

        assertEquals(100, result.riskScore());
        assertEquals("KNOWN_THREAT_MATCH", result.verdict());
    }

    @Test
    void highHeuristicScoreProducesHighRisk() {
        var result = scoring.assess(false, 50);

        assertEquals(50, result.riskScore());
        assertEquals("HIGH_RISK", result.verdict());
    }

    @Test
    void intermediateScoreProducesSuspiciousVerdict() {
        var result = scoring.assess(false, 30);

        assertEquals(30, result.riskScore());
        assertEquals("SUSPICIOUS", result.verdict());
    }

    @Test
    void lowScoreDoesNotClaimTheUrlIsVerifiedSafe() {
        var result = scoring.assess(false, 0);

        assertEquals("NO_KNOWN_THREAT_FOUND", result.verdict());
        assertEquals("LIMITED_EVIDENCE", result.evidenceLevel());
    }
}