package com.bharath.qr_phishing_detector.dto;

import java.time.Instant;

public record FeedStatusResponse(
        String sourceKey,
        String displayName,
        String feedType,
        boolean enabled,
        String lastStatus,
        Instant lastAttemptAt,
        Instant lastSuccessfulSyncAt,
        Long latestRunId,
        String latestRunOutcome,
        Instant latestRunStartedAt,
        Instant latestRunCompletedAt,
        Integer recordsDownloaded,
        Integer recordsProcessed,
        Integer recordsSkipped,
        Integer recordsInserted,
        Integer recordsUpdated
) {
}