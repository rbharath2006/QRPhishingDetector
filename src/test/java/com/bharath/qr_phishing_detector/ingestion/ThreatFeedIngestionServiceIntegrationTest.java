package com.bharath.qr_phishing_detector.ingestion;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Locale;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(properties = {
        "app.feeds.local-test.run-on-startup=false",
        "app.feeds.phishtank.scheduler-enabled=false"
})
class ThreatFeedIngestionServiceIntegrationTest {

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private ThreatFeedIngestionService ingestionService;

    private String sourceKey;

    @BeforeEach
    void createTemporarySource() {
        sourceKey = "TEST_"
                + UUID.randomUUID()
                .toString()
                .replace("-", "")
                .toUpperCase(Locale.ROOT);

        jdbc.update(
                """
                INSERT INTO feed_source (
                    source_key,
                    display_name,
                    feed_type,
                    enabled,
                    refresh_interval_seconds,
                    last_status
                )
                VALUES (?, 'Integration Test Source',
                        'PHISHING_URLS', TRUE, 86400, 'NEVER_RUN')
                """,
                sourceKey
        );
    }

    @AfterEach
    void cleanUpTemporarySource() {
        if (sourceKey == null) {
            return;
        }

        jdbc.update(
                """
                DELETE FROM threat_indicator
                WHERE source_id = (
                    SELECT id FROM feed_source WHERE source_key = ?
                )
                """,
                sourceKey
        );

        jdbc.update(
                """
                DELETE FROM feed_sync_run
                WHERE source_id = (
                    SELECT id FROM feed_source WHERE source_key = ?
                )
                """,
                sourceKey
        );

        jdbc.update(
                "DELETE FROM feed_source WHERE source_key = ?",
                sourceKey
        );
    }

    @Test
    void insertsUniqueUrlsAndSkipsDuplicateInputs() {
        var result = ingestionService.ingestUrlSnapshot(
                sourceKey,
                List.of(
                        "https://alpha.demo.test/login",
                        "HTTPS://ALPHA.DEMO.TEST:443/login#section",
                        "https://beta.demo.test/account"
                )
        );

        assertEquals(3, result.recordsDownloaded());
        assertEquals(2, result.recordsProcessed());
        assertEquals(1, result.recordsSkipped());
        assertEquals(2, result.recordsInserted());
        assertEquals(0, result.recordsUpdated());
        assertTrue(result.staleMarkingApplied());

        assertEquals(2, countIndicators());
    }

    @Test
    void repeatedSnapshotUpdatesExistingRecordsWithoutDuplicates() {
        List<String> urls = List.of(
                "https://alpha.demo.test/login",
                "https://beta.demo.test/account"
        );

        var first = ingestionService.ingestUrlSnapshot(
                sourceKey, urls
        );

        var second = ingestionService.ingestUrlSnapshot(
                sourceKey, urls
        );

        assertEquals(2, first.recordsInserted());
        assertEquals(0, second.recordsInserted());
        assertEquals(2, second.recordsUpdated());
        assertEquals(2, countIndicators());
    }

    @Test
    void emptyOrInvalidSnapshotDoesNotEraseExistingIndicators() {
        ingestionService.ingestUrlSnapshot(
                sourceKey,
                List.of(
                        "https://alpha.demo.test/login",
                        "https://beta.demo.test/account"
                )
        );

        assertThrows(
                IllegalStateException.class,
                () -> ingestionService.ingestUrlSnapshot(
                        sourceKey,
                        List.of("this-is-not-a-valid-http-url")
                )
        );

        // The previous successful snapshot must remain intact.
        assertEquals(2, countIndicators());
        assertEquals(2, countActiveIndicators());
        assertEquals("FAILED", latestRunOutcome());
    }

    @Test
    void invalidEntryPreventsUnsafeStaleMarking() {
        ingestionService.ingestUrlSnapshot(
                sourceKey,
                List.of(
                        "https://alpha.demo.test/login",
                        "https://beta.demo.test/account"
                )
        );

        var result = ingestionService.ingestUrlSnapshot(
                sourceKey,
                List.of(
                        "https://alpha.demo.test/login",
                        "this-is-not-a-valid-http-url"
                )
        );

        assertEquals(1, result.recordsProcessed());
        assertEquals(1, result.recordsSkipped());
        assertFalse(result.staleMarkingApplied());

        // An incomplete snapshot must not stale the omitted URL.
        assertEquals(2, countActiveIndicators());
    }

    private int countIndicators() {
        return jdbc.queryForObject(
                """
                SELECT COUNT(*)
                FROM threat_indicator ti
                JOIN feed_source fs ON fs.id = ti.source_id
                WHERE fs.source_key = ?
                  AND ti.indicator_type = 'EXACT_URL'
                """,
                Integer.class,
                sourceKey
        );
    }

    private int countActiveIndicators() {
        return jdbc.queryForObject(
                """
                SELECT COUNT(*)
                FROM threat_indicator ti
                JOIN feed_source fs ON fs.id = ti.source_id
                WHERE fs.source_key = ?
                  AND ti.indicator_type = 'EXACT_URL'
                  AND ti.status = 'ACTIVE'
                """,
                Integer.class,
                sourceKey
        );
    }

    private String latestRunOutcome() {
        return jdbc.queryForObject(
                """
                SELECT outcome
                FROM feed_sync_run
                WHERE source_id = (
                    SELECT id FROM feed_source WHERE source_key = ?
                )
                ORDER BY id DESC
                LIMIT 1
                """,
                String.class,
                sourceKey
        );
    }
}