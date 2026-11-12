package com.bharath.qr_phishing_detector.ingestion;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@SpringBootTest(properties = {
        "app.feeds.local-test.run-on-startup=false",
        "app.feeds.phishtank.scheduler-enabled=false",
        "app.feeds.remote-text.enabled=false",
        "app.feeds.remote-text.source-key=REMOTE_SYNC_TEST",
        "app.feeds.remote-text.url=https://feeds.example.org/test.txt",
        "app.feeds.remote-text.allowed-host=feeds.example.org"
})
class RemoteTextFeedSyncServiceIntegrationTest {

    private static final String SOURCE_KEY = "REMOTE_SYNC_TEST";
    private static final String FEED_URL =
            "https://feeds.example.org/test.txt";
    private static final String ALLOWED_HOST = "feeds.example.org";

    private static final String URL_A =
            "https://alpha.remote-sync-test.test/login";
    private static final String URL_B =
            "https://beta.remote-sync-test.test/account";

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private RemoteTextFeedSyncService syncService;

    @Autowired
    private ThreatFeedIngestionService ingestionService;

    @MockitoBean
    private RemoteTextFeedClient feedClient;

    @BeforeEach
    void createTemporarySource() {
        jdbc.update(
                """
                INSERT INTO feed_source (
                    source_key,
                    display_name,
                    feed_type,
                    feed_url,
                    enabled,
                    refresh_interval_seconds,
                    last_status
                )
                VALUES (
                    ?, 'Remote Sync Integration Test',
                    'PHISHING_URLS', ?, TRUE, 43200, 'NEVER_RUN'
                )
                ON CONFLICT (source_key)
                DO UPDATE SET
                    enabled = TRUE,
                    feed_type = 'PHISHING_URLS',
                    feed_url = EXCLUDED.feed_url
                """,
                SOURCE_KEY,
                FEED_URL
        );
    }

    @AfterEach
    void removeTemporarySource() {
        jdbc.update(
                """
                DELETE FROM threat_indicator
                WHERE source_id = (
                    SELECT id FROM feed_source WHERE source_key = ?
                )
                """,
                SOURCE_KEY
        );

        jdbc.update(
                """
                DELETE FROM feed_sync_run
                WHERE source_id = (
                    SELECT id FROM feed_source WHERE source_key = ?
                )
                """,
                SOURCE_KEY
        );

        jdbc.update(
                "DELETE FROM feed_source WHERE source_key = ?",
                SOURCE_KEY
        );
    }

    @Test
    void successfulFetchImportsIndicators() throws Exception {
        when(feedClient.fetchAndParse(FEED_URL, ALLOWED_HOST))
                .thenReturn(List.of(URL_A, URL_B));

        syncService.syncOnce();

        assertEquals(2, countActiveIndicators());
        assertEquals("SUCCESS", latestRunOutcome());

        verify(feedClient).fetchAndParse(FEED_URL, ALLOWED_HOST);
    }

    @Test
    void failedDownloadPreservesPreviousIndicators() throws Exception {
        // Establish a known-good snapshot before simulating a failure.
        ingestionService.ingestUrlSnapshot(
                SOURCE_KEY,
                List.of(URL_A)
        );

        when(feedClient.fetchAndParse(FEED_URL, ALLOWED_HOST))
                .thenThrow(new IOException("Simulated feed outage"));

        syncService.syncOnce();

        assertEquals(1, countActiveIndicators());
        assertEquals("FAILED", latestRunOutcome());

        verify(feedClient).fetchAndParse(FEED_URL, ALLOWED_HOST);
    }

    @Test
    void emptyRemoteFeedDoesNotEraseExistingIndicators()
            throws Exception {

        ingestionService.ingestUrlSnapshot(
                SOURCE_KEY,
                List.of(URL_A)
        );

        when(feedClient.fetchAndParse(FEED_URL, ALLOWED_HOST))
                .thenReturn(List.of());

        syncService.syncOnce();

        assertEquals(1, countActiveIndicators());
        assertEquals("FAILED", latestRunOutcome());
    }

    @Test
    void disabledSourceDoesNotFetchFeed() {

        jdbc.update(
                """
                UPDATE feed_source
                SET enabled = FALSE
                WHERE source_key = ?
                """,
                SOURCE_KEY
        );

        syncService.syncOnce();

        verifyNoInteractions(feedClient);
        assertEquals(0, countRuns());
    }

    private int countActiveIndicators() {
        return jdbc.queryForObject(
                """
                SELECT COUNT(*)
                FROM threat_indicator ti
                JOIN feed_source fs ON fs.id = ti.source_id
                WHERE fs.source_key = ?
                  AND ti.status = 'ACTIVE'
                """,
                Integer.class,
                SOURCE_KEY
        );
    }

    private int countRuns() {
        return jdbc.queryForObject(
                """
                SELECT COUNT(*)
                FROM feed_sync_run sr
                JOIN feed_source fs ON fs.id = sr.source_id
                WHERE fs.source_key = ?
                """,
                Integer.class,
                SOURCE_KEY
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
                SOURCE_KEY
        );
    }
}