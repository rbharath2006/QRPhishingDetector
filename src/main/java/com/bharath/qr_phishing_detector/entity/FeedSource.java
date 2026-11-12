package com.bharath.qr_phishing_detector.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "feed_source")
public class FeedSource {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "source_key", nullable = false,
            unique = true, length = 80)
    private String sourceKey;

    @Column(name = "display_name", nullable = false, length = 150)
    private String displayName;

    @Enumerated(EnumType.STRING)
    @Column(name = "feed_type", nullable = false, length = 40)
    private FeedType feedType;

    @Column(name = "feed_url", columnDefinition = "text")
    private String feedUrl;

    @Column(name = "enabled", nullable = false)
    private boolean enabled;

    @Column(name = "refresh_interval_seconds", nullable = false)
    private int refreshIntervalSeconds;

    @Column(name = "last_attempt_at",
            insertable = false, updatable = false)
    private Instant lastAttemptAt;

    @Column(name = "last_successful_sync_at",
            insertable = false, updatable = false)
    private Instant lastSuccessfulSyncAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "last_status", nullable = false, length = 20)
    private LastStatus lastStatus;

    @Column(name = "created_at",
            insertable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at",
            insertable = false, updatable = false)
    private Instant updatedAt;

    protected FeedSource() {
        // Required by JPA
    }

    public Long getId() {
        return id;
    }

    public String getSourceKey() {
        return sourceKey;
    }

    public String getDisplayName() {
        return displayName;
    }

    public FeedType getFeedType() {
        return feedType;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public enum FeedType {
        PHISHING_URLS,
        MALWARE_URLS,
        DOMAIN_REPUTATION,
        MIXED
    }

    public enum LastStatus {
        NEVER_RUN,
        SUCCESS,
        FAILED
    }
}