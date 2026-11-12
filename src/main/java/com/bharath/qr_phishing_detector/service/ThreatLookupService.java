package com.bharath.qr_phishing_detector.service;

import com.bharath.qr_phishing_detector.detection.RiskScoringService;
import com.bharath.qr_phishing_detector.detection.URLHeuristicsService;
import com.bharath.qr_phishing_detector.dto.ThreatLookupResponse;
import com.bharath.qr_phishing_detector.entity.ThreatIndicator;
import com.bharath.qr_phishing_detector.entity.ThreatIndicator.IndicatorStatus;
import com.bharath.qr_phishing_detector.entity.ThreatIndicator.IndicatorType;
import com.bharath.qr_phishing_detector.repository.ThreatIndicatorRepository;
import com.bharath.qr_phishing_detector.validation.RegistrableDomainService;
import com.bharath.qr_phishing_detector.validation.URLNormalizationService;
import com.bharath.qr_phishing_detector.validation.URLNormalizationService.NormalizedUrl;
import com.bharath.qr_phishing_detector.detection.BrandImpersonationService;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class ThreatLookupService {

    private final ThreatIndicatorRepository repository;
    private final URLNormalizationService normalizer;
    private final RegistrableDomainService registrableDomainService;
    private final URLHeuristicsService heuristicsService;
    private final RiskScoringService riskScoringService;
    private final BrandImpersonationService brandImpersonationService;

    public ThreatLookupService(
            ThreatIndicatorRepository repository,
            URLNormalizationService normalizer,
            RegistrableDomainService registrableDomainService,
            URLHeuristicsService heuristicsService,
            RiskScoringService riskScoringService,
            BrandImpersonationService brandImpersonationService
    ) {
        this.repository = repository;
        this.normalizer = normalizer;
        this.registrableDomainService = registrableDomainService;
        this.heuristicsService = heuristicsService;
        this.riskScoringService = riskScoringService;
        this.brandImpersonationService = brandImpersonationService;
    }

    @Transactional(readOnly = true)
    public ThreatLookupResponse lookup(String inputUrl) {

        NormalizedUrl normalized = normalizer.normalize(inputUrl);
        Instant now = Instant.now();

        String registrableDomain = registrableDomainService
                .findRegistrableDomain(normalized.hostname())
                .orElse(null);

        URLHeuristicsService.Analysis heuristicAnalysis =
                heuristicsService.analyze(inputUrl, normalized);
        BrandImpersonationService.Analysis brandAnalysis =
                brandImpersonationService.analyze(normalized.hostname());

        int combinedHeuristicScore = Math.min(
                100,
                heuristicAnalysis.score() + brandAnalysis.score()
        );

        Map<Long, ThreatLookupResponse.ThreatMatch> matches =
                new LinkedHashMap<>();

        // 1. Exact normalized URL lookup.
        findAndCollect(
                IndicatorType.EXACT_URL,
                normalized.canonicalUrl(),
                now,
                matches
        );

        // 2. Exact hostname lookup.
        findAndCollect(
                IndicatorType.HOSTNAME,
                normalized.hostname(),
                now,
                matches
        );

        // 3. Registrable-domain lookup, when derivation is possible.
        if (registrableDomain != null) {
            findAndCollect(
                    IndicatorType.REGISTRABLE_DOMAIN,
                    registrableDomain,
                    now,
                    matches
            );
        }

        List<ThreatLookupResponse.ThreatMatch> matchList =
                new ArrayList<>(matches.values());

        boolean knownThreatMatch = !matchList.isEmpty();

        RiskScoringService.Assessment assessment =
                riskScoringService.assess(
                        knownThreatMatch,
                        combinedHeuristicScore
                );

        List<String> explanations =
                new ArrayList<>(heuristicAnalysis.reasons());
        explanations.addAll(brandAnalysis.reasons());

        if (registrableDomain != null) {
            explanations.add(
                    "Registrable domain derived using public-suffix rules: "
                            + registrableDomain + "."
            );
        } else {
            explanations.add(
                    "A registrable public DNS domain could not be derived "
                            + "for this hostname."
            );
        }

        if (knownThreatMatch) {
            for (ThreatLookupResponse.ThreatMatch match : matchList) {
                explanations.add(
                        "An active local indicator matched at scope "
                                + match.indicatorType()
                                + ", category "
                                + match.threatType()
                                + ", reported by "
                                + match.sourceName()
                                + "."
                );
            }
        } else if (registrableDomain != null) {
            explanations.add(
                    "No active exact-URL, hostname, or registrable-domain "
                            + "indicator matched the local database."
            );
        } else {
            explanations.add(
                    "No active exact-URL or hostname indicator matched "
                            + "the local database."
            );
        }

        if (heuristicAnalysis.reasons().isEmpty()) {
            explanations.add(
                    "No warning was triggered by the initial structural "
                            + "heuristics."
            );
        }

        explanations.add(
                "The risk score is a preliminary rule-based index, "
                        + "not a probability of maliciousness."
        );

        explanations.add(
                "Live reputation providers and sandbox analysis have "
                        + "not yet been integrated into this endpoint."
        );

        return new ThreatLookupResponse(
                assessment.riskScore(),
                assessment.verdict(),
                assessment.evidenceLevel(),
                knownThreatMatch,
                normalized.hostname(),
                registrableDomain,
                now,
                List.copyOf(matchList),
                List.copyOf(explanations)
        );
    }

    private void findAndCollect(
            IndicatorType type,
            String value,
            Instant now,
            Map<Long, ThreatLookupResponse.ThreatMatch> matches
    ) {
        String hash = normalizer.sha256Hex(value);

        List<ThreatIndicator> indicators =
                repository.findCurrentMatches(
                        type,
                        hash,
                        IndicatorStatus.ACTIVE,
                        now
                );

        for (ThreatIndicator indicator : indicators) {
            matches.put(
                    indicator.getId(),
                    new ThreatLookupResponse.ThreatMatch(
                            indicator.getIndicatorType().name(),
                            indicator.getThreatType().name(),
                            indicator.getSource().getDisplayName(),
                            indicator.getSourceConfidence(),
                            indicator.getSourceUpdatedAt(),
                            indicator.getLastSeenAt()
                    )
            );
        }
    }
}