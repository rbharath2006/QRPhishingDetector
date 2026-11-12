package com.bharath.qr_phishing_detector.ingestion;

import com.bharath.qr_phishing_detector.validation.URLNormalizationService;
import com.bharath.qr_phishing_detector.validation.URLNormalizationService.NormalizedUrl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

@Service
public class ThreatFeedIngestionService {

    private static final Logger log =
            LoggerFactory.getLogger(ThreatFeedIngestionService.class);

    private static final int BATCH_SIZE = 500;

    private static final String UPSERT_SQL = """
        INSERT INTO threat_indicator (
            source_id,
            indicator_type,
            normalized_value,
            normalized_value_hash,
            threat_type,
            source_confidence,
            status,
            first_seen_at,
            last_seen_at,
            source_updated_at,
            expires_at,
            last_seen_sync_run_id,
            created_at,
            updated_at
        )
        VALUES (
            ?, 'EXACT_URL', ?, ?, ?, NULL, 'ACTIVE',
            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP,
            NULL, NULL, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        )
        ON CONFLICT (
            source_id,
            indicator_type,
            normalized_value_hash
        )
        DO UPDATE SET
            normalized_value = EXCLUDED.normalized_value,
            threat_type = EXCLUDED.threat_type,
            source_confidence = EXCLUDED.source_confidence,
            status = 'ACTIVE',
            first_seen_at = COALESCE(
                threat_indicator.first_seen_at,
                EXCLUDED.first_seen_at
            ),
            last_seen_at = CURRENT_TIMESTAMP,
            source_updated_at = EXCLUDED.source_updated_at,
            expires_at = EXCLUDED.expires_at,
            last_seen_sync_run_id = EXCLUDED.last_seen_sync_run_id,
            updated_at = CURRENT_TIMESTAMP
        """;

    private final JdbcTemplate jdbc;
    private final URLNormalizationService normalizer;
    private final TransactionTemplate transactionTemplate;

    public ThreatFeedIngestionService(
            JdbcTemplate jdbc,
            URLNormalizationService normalizer,
            PlatformTransactionManager transactionManager
    ) {
        this.jdbc = jdbc;
        this.normalizer = normalizer;
        this.transactionTemplate =
                new TransactionTemplate(transactionManager);
    }

    public ImportSummary ingestUrlSnapshot(
            String sourceKey,
            List<String> rawUrls
    ) {
        SourceInfo source = findSource(sourceKey);

        if (!source.enabled()) {
            throw new IllegalStateException(
                    "The requested feed source is disabled."
            );
        }

        // Create the run outside the import transaction so failures
        // can still be recorded after an import transaction rolls back.
        long runId = Objects.requireNonNull(
                jdbc.queryForObject(
                        """
                        INSERT INTO feed_sync_run (source_id, outcome)
                        VALUES (?, 'RUNNING')
                        RETURNING id
                        """,
                        Long.class,
                        source.id()
                )
        );

        jdbc.update(
                """
                UPDATE feed_source
                SET last_attempt_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                source.id()
        );

        try {
            List<String> inputs = rawUrls == null
                    ? List.of()
                    : rawUrls;

            Map<String, Candidate> uniqueCandidates =
                    new LinkedHashMap<>();

            int invalidRows = 0;
            int duplicateRows = 0;

            for (String rawUrl : inputs) {
                if (rawUrl == null || rawUrl.isBlank()) {
                    invalidRows++;
                    continue;
                }

                try {
                    NormalizedUrl normalized =
                            normalizer.normalize(rawUrl);

                    String canonicalUrl = normalized.canonicalUrl();
                    String hash = normalizer.sha256Hex(canonicalUrl);

                    Candidate candidate =
                            new Candidate(canonicalUrl, hash);

                    if (uniqueCandidates.putIfAbsent(hash, candidate) != null) {
                        duplicateRows++;
                    }

                } catch (RuntimeException ex) {
                    // Skip invalid entries without logging the submitted URL.
                    invalidRows++;
                }
            }

            List<Candidate> candidates =
                    List.copyOf(uniqueCandidates.values());

            if (candidates.isEmpty()) {
                throw new IllegalArgumentException(
                        "The snapshot contains no valid URL indicators."
                );
            }

            final int downloadedCount = inputs.size();
            final int invalidCount = invalidRows;
            final int skippedCount = invalidRows + duplicateRows;

            final String threatType =
                    determineThreatType(source.feedType());

            ImportSummary summary = transactionTemplate.execute(status -> {

                Set<String> existingHashes =
                        findExistingHashes(source.id(), candidates);

                int inserted = 0;
                int updated = 0;

                List<Object[]> batch = new ArrayList<>(BATCH_SIZE);

                for (Candidate candidate : candidates) {
                    if (existingHashes.contains(candidate.hash())) {
                        updated++;
                    } else {
                        inserted++;
                    }

                    batch.add(new Object[]{
                            source.id(),
                            candidate.normalizedUrl(),
                            candidate.hash(),
                            threatType,
                            runId
                    });

                    if (batch.size() >= BATCH_SIZE) {
                        jdbc.batchUpdate(UPSERT_SQL, batch);
                        batch.clear();
                    }
                }

                if (!batch.isEmpty()) {
                    jdbc.batchUpdate(UPSERT_SQL, batch);
                }

                // Do not stale older indicators if the input contained
                // invalid records: the snapshot may be incomplete.
                boolean staleMarkingApplied = invalidCount == 0;

                if (staleMarkingApplied) {
                    jdbc.update(
                            """
                            UPDATE threat_indicator
                            SET status = 'STALE',
                                expires_at = CURRENT_TIMESTAMP,
                                updated_at = CURRENT_TIMESTAMP
                            WHERE source_id = ?
                              AND indicator_type = 'EXACT_URL'
                              AND status = 'ACTIVE'
                              AND last_seen_sync_run_id IS DISTINCT FROM ?
                            """,
                            source.id(),
                            runId
                    );
                }

                jdbc.update(
                        """
                        UPDATE feed_sync_run
                        SET outcome = 'SUCCESS',
                            completed_at = CURRENT_TIMESTAMP,
                            records_downloaded = ?,
                            records_inserted = ?,
                            records_updated = ?,
                            records_processed = ?,
                            records_skipped = ?,
                            error_summary = NULL
                        WHERE id = ?
                        """,
                        downloadedCount,
                        inserted,
                        updated,
                        candidates.size(),
                        skippedCount,
                        runId
                );

                jdbc.update(
                        """
                        UPDATE feed_source
                        SET last_attempt_at = CURRENT_TIMESTAMP,
                            last_successful_sync_at = CURRENT_TIMESTAMP,
                            last_status = 'SUCCESS',
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                        """,
                        source.id()
                );

                return new ImportSummary(
                        runId,
                        downloadedCount,
                        candidates.size(),
                        skippedCount,
                        inserted,
                        updated,
                        staleMarkingApplied
                );
            });

            ImportSummary result = Objects.requireNonNull(summary);

            log.info(
                    "Feed import completed: source={}, runId={}, " +
                            "processed={}, skipped={}, inserted={}, updated={}, " +
                            "staleMarkingApplied={}",
                    sourceKey,
                    result.syncRunId(),
                    result.recordsProcessed(),
                    result.recordsSkipped(),
                    result.recordsInserted(),
                    result.recordsUpdated(),
                    result.staleMarkingApplied()
            );

            return result;

        } catch (RuntimeException ex) {
            try {
                jdbc.update(
                        """
                        UPDATE feed_sync_run
                        SET outcome = 'FAILED',
                            completed_at = CURRENT_TIMESTAMP,
                            error_summary = ?
                        WHERE id = ?
                        """,
                        "Import failed: " + ex.getClass().getSimpleName(),
                        runId
                );

                jdbc.update(
                        """
                        UPDATE feed_source
                        SET last_attempt_at = CURRENT_TIMESTAMP,
                            last_status = 'FAILED',
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                        """,
                        source.id()
                );

            } catch (RuntimeException loggingException) {
                log.error(
                        "Failed to record ingestion failure for source {}",
                        sourceKey
                );
            }

            throw new IllegalStateException(
                    "Feed snapshot import failed for source "
                            + sourceKey + ".",
                    ex
            );
        }
    }

    private SourceInfo findSource(String sourceKey) {
        List<SourceInfo> sources = jdbc.query(
                """
                SELECT id, enabled, feed_type
                FROM feed_source
                WHERE source_key = ?
                """,
                (rs, rowNum) -> new SourceInfo(
                        rs.getLong("id"),
                        rs.getBoolean("enabled"),
                        rs.getString("feed_type")
                ),
                sourceKey
        );

        if (sources.isEmpty()) {
            throw new IllegalArgumentException(
                    "Feed source is not registered."
            );
        }

        return sources.get(0);
    }

    private String determineThreatType(String feedType) {
        return switch (feedType) {
            case "PHISHING_URLS" -> "PHISHING";
            case "MALWARE_URLS" -> "MALWARE_DISTRIBUTION";
            case "MIXED" -> "UNKNOWN";
            default -> throw new IllegalStateException(
                    "This source type is not configured for URL snapshots."
            );
        };
    }

    private Set<String> findExistingHashes(
            long sourceId,
            List<Candidate> candidates
    ) {
        Set<String> existing = new HashSet<>();

        for (int start = 0; start < candidates.size(); start += BATCH_SIZE) {
            int end = Math.min(start + BATCH_SIZE, candidates.size());

            List<Candidate> chunk = candidates.subList(start, end);

            String placeholders = String.join(
                    ",",
                    java.util.Collections.nCopies(chunk.size(), "?")
            );

            String sql = """
                SELECT normalized_value_hash
                FROM threat_indicator
                WHERE source_id = ?
                  AND indicator_type = 'EXACT_URL'
                  AND normalized_value_hash IN (
                """ + placeholders + ")";

            List<Object> parameters = new ArrayList<>();
            parameters.add(sourceId);

            for (Candidate candidate : chunk) {
                parameters.add(candidate.hash());
            }

            existing.addAll(
                    jdbc.queryForList(
                            sql,
                            String.class,
                            parameters.toArray()
                    )
            );
        }

        return existing;
    }

    private record SourceInfo(
            long id,
            boolean enabled,
            String feedType
    ) {
    }

    private record Candidate(
            String normalizedUrl,
            String hash
    ) {
    }

    public record ImportSummary(
            long syncRunId,
            int recordsDownloaded,
            int recordsProcessed,
            int recordsSkipped,
            int recordsInserted,
            int recordsUpdated,
            boolean staleMarkingApplied
    ) {
    }
}