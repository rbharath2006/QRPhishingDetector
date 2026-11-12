package com.bharath.qr_phishing_detector.ingestion;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

@Service
public class RemoteTextFeedSyncService {

    private static final Logger log =
            LoggerFactory.getLogger(RemoteTextFeedSyncService.class);

    private final JdbcTemplate jdbc;
    private final RemoteTextFeedClient feedClient;
    private final ThreatFeedIngestionService ingestionService;

    @Value("${app.feeds.remote-text.url:}")
    private String feedUrl;

    @Value("${app.feeds.remote-text.allowed-host:}")
    private String allowedHost;

    @Value("${app.feeds.remote-text.source-key:AUTHORISED_PHISHING_FEED}")
    private String sourceKey;

    public RemoteTextFeedSyncService(
            JdbcTemplate jdbc,
            RemoteTextFeedClient feedClient,
            ThreatFeedIngestionService ingestionService
    ) {
        this.jdbc = jdbc;
        this.feedClient = feedClient;
        this.ingestionService = ingestionService;
    }

    public void syncOnce() {

        List<SourceState> sources = jdbc.query(
                """
                SELECT id, enabled
                FROM feed_source
                WHERE source_key = ?
                """,
                (rs, rowNum) -> new SourceState(
                        rs.getLong("id"),
                        rs.getBoolean("enabled")
                ),
                sourceKey
        );

        if (sources.isEmpty()) {
            log.error("Configured external feed source does not exist.");
            return;
        }

        SourceState source = sources.get(0);

        if (!source.enabled()) {
            log.info("External feed source is disabled.");
            return;
        }

        if (feedUrl == null || feedUrl.isBlank()
                || allowedHost == null || allowedHost.isBlank()) {
            recordFailure(source.id(), "REMOTE_FEED_CONFIGURATION_MISSING");
            return;
        }

        final List<String> urls;

        try {
            urls = feedClient.fetchAndParse(feedUrl, allowedHost);

            if (urls.isEmpty()) {
                throw new IOException(
                        "Remote feed contains no URL entries."
                );
            }

        } catch (Exception ex) {

            if (ex instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }

            recordFailure(
                    source.id(),
                    "REMOTE_FEED_FETCH_OR_PARSE_FAILED_"
                            + ex.getClass().getSimpleName()
                            .toUpperCase(Locale.ROOT)
            );

            log.warn(
                    "External feed download or parsing failed ({}).",
                    ex.getClass().getSimpleName()
            );

            return;
        }

        try {
            ThreatFeedIngestionService.ImportSummary summary =
                    ingestionService.ingestUrlSnapshot(sourceKey, urls);

            log.info(
                    "External feed sync completed: source={}, runId={}, " +
                            "processed={}, skipped={}, inserted={}, updated={}",
                    sourceKey,
                    summary.syncRunId(),
                    summary.recordsProcessed(),
                    summary.recordsSkipped(),
                    summary.recordsInserted(),
                    summary.recordsUpdated()
            );

        } catch (RuntimeException ex) {
            // ThreatFeedIngestionService records database import failures.
            log.error(
                    "External feed database import failed ({}).",
                    ex.getClass().getSimpleName()
            );
        }
    }

    private void recordFailure(long sourceId, String safeReason) {

        jdbc.update(
                """
                INSERT INTO feed_sync_run (
                    source_id,
                    outcome,
                    completed_at,
                    error_summary
                )
                VALUES (?, 'FAILED', CURRENT_TIMESTAMP, ?)
                """,
                sourceId,
                safeReason
        );

        jdbc.update(
                """
                UPDATE feed_source
                SET last_attempt_at = CURRENT_TIMESTAMP,
                    last_status = 'FAILED',
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                sourceId
        );
    }

    private record SourceState(
            long id,
            boolean enabled
    ) {
    }
}