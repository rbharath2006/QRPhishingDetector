package com.bharath.qr_phishing_detector.detection;

import org.springframework.stereotype.Service;

@Service
public class RiskScoringService {

    public Assessment assess(
            boolean knownThreatMatch,
            int heuristicScore
    ) {
        // A current local indicator match takes priority over heuristics.
        if (knownThreatMatch) {
            return new Assessment(
                    100,
                    "KNOWN_THREAT_MATCH",
                    "STRONG_INDICATOR_EVIDENCE"
            );
        }

        if (heuristicScore >= 50) {
            return new Assessment(
                    heuristicScore,
                    "HIGH_RISK",
                    "MULTIPLE_STRUCTURAL_WARNINGS"
            );
        }

        if (heuristicScore >= 25) {
            return new Assessment(
                    heuristicScore,
                    "SUSPICIOUS",
                    "STRUCTURAL_WARNINGS"
            );
        }

        return new Assessment(
                heuristicScore,
                "NO_KNOWN_THREAT_FOUND",
                "LIMITED_EVIDENCE"
        );
    }

    public record Assessment(
            int riskScore,
            String verdict,
            String evidenceLevel
    ) {
    }
}