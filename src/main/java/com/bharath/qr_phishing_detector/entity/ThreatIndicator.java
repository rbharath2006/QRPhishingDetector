package com.bharath.qr_phishing_detector.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "threat_indicator")
public class ThreatIndicator {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "source_id", nullable = false)
    private FeedSource source;

    @Enumerated(EnumType.STRING)
    @Column(name = "indicator_type", nullable = false, length = 30)
    private IndicatorType indicatorType;

    @Column(name = "normalized_value",
            nullable = false, columnDefinition = "text")
    private String normalizedValue;

    @Column(
            name = "normalized_value_hash",
            nullable = false,
            length = 64
    )
    private String normalizedValueHash;

    @Enumerated(EnumType.STRING)
    @Column(name = "threat_type", nullable = false, length = 40)
    private ThreatType threatType;

    @Column(name = "source_confidence")
    private Integer sourceConfidence;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private IndicatorStatus status;

    @Column(name = "first_seen_at")
    private Instant firstSeenAt;

    @Column(name = "last_seen_at")
    private Instant lastSeenAt;

    @Column(name = "source_updated_at")
    private Instant sourceUpdatedAt;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "created_at",
            insertable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at",
            insertable = false, updatable = false)
    private Instant updatedAt;

    protected ThreatIndicator() {
        // Required by JPA
    }

    public Long getId() {
        return id;
    }

    public FeedSource getSource() {
        return source;
    }

    public IndicatorType getIndicatorType() {
        return indicatorType;
    }

    public ThreatType getThreatType() {
        return threatType;
    }

    public Integer getSourceConfidence() {
        return sourceConfidence;
    }

    public Instant getLastSeenAt() {
        return lastSeenAt;
    }

    public Instant getSourceUpdatedAt() {
        return sourceUpdatedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public enum IndicatorType {
        EXACT_URL,
        HOSTNAME,
        REGISTRABLE_DOMAIN
    }

    public enum ThreatType {
        PHISHING,
        MALWARE_DISTRIBUTION,
        SCAM,
        UNKNOWN
    }

    public enum IndicatorStatus {
        ACTIVE,
        STALE,
        REVOKED,
        EXPIRED
    }
}