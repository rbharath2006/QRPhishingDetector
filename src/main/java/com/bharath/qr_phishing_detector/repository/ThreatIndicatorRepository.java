package com.bharath.qr_phishing_detector.repository;

import com.bharath.qr_phishing_detector.entity.ThreatIndicator;
import com.bharath.qr_phishing_detector.entity.ThreatIndicator.IndicatorStatus;
import com.bharath.qr_phishing_detector.entity.ThreatIndicator.IndicatorType;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;

public interface ThreatIndicatorRepository
        extends JpaRepository<ThreatIndicator, Long> {

    @Query("""
        SELECT ti
        FROM ThreatIndicator ti
        JOIN FETCH ti.source src
        WHERE ti.indicatorType = :indicatorType
          AND ti.normalizedValueHash = :hash
          AND ti.status = :status
          AND (ti.expiresAt IS NULL OR ti.expiresAt > :now)
          AND src.enabled = TRUE
        """)
    List<ThreatIndicator> findCurrentMatches(
            @Param("indicatorType") IndicatorType indicatorType,
            @Param("hash") String hash,
            @Param("status") IndicatorStatus status,
            @Param("now") Instant now
    );
}