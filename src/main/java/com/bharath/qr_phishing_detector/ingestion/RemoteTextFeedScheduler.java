package com.bharath.qr_phishing_detector.ingestion;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(
        prefix = "app.feeds.remote-text",
        name = "enabled",
        havingValue = "true"
)
public class RemoteTextFeedScheduler {

    private final RemoteTextFeedSyncService syncService;

    public RemoteTextFeedScheduler(
            RemoteTextFeedSyncService syncService
    ) {
        this.syncService = syncService;
    }

    @Scheduled(
            initialDelayString =
                    "${app.feeds.remote-text.initial-delay-ms:15000}",
            fixedDelayString =
                    "${app.feeds.remote-text.refresh-delay-ms:43200000}"
    )
    public void refreshFeed() {
        syncService.syncOnce();
    }
}