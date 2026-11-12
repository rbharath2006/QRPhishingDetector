package com.bharath.qr_phishing_detector.service;

import com.bharath.qr_phishing_detector.dto.FeedStatusResponse;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;

@Service
public class FeedStatusService {

    private final JdbcTemplate jdbc;

    public FeedStatusService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @Transactional(readOnly = true)
    public List<FeedStatusResponse> getAllStatuses() {

        String sql = """
            SELECT
                fs.source_key,
                fs.display_name,
                fs.feed_type,
                fs.enabled,
                fs.last_status,
                fs.last_attempt_at,
                fs.last_successful_sync_at,
                r.id AS run_id,
                r.outcome AS run_outcome,
                r.started_at AS run_started_at,
                r.completed_at AS run_completed_at,
                r.records_downloaded,
                r.records_processed,
                r.records_skipped,
                r.records_inserted,
                r.records_updated
            FROM feed_source fs
            LEFT JOIN LATERAL (
                SELECT *
                FROM feed_sync_run sr
                WHERE sr.source_id = fs.id
                ORDER BY sr.id DESC
                LIMIT 1
            ) r ON TRUE
            ORDER BY fs.source_key
            """;

        return jdbc.query(sql, (rs, rowNum) ->
                new FeedStatusResponse(
                        rs.getString("source_key"),
                        rs.getString("display_name"),
                        rs.getString("feed_type"),
                        rs.getBoolean("enabled"),
                        rs.getString("last_status"),
                        toInstant(rs.getTimestamp("last_attempt_at")),
                        toInstant(rs.getTimestamp("last_successful_sync_at")),
                        rs.getObject("run_id", Long.class),
                        rs.getString("run_outcome"),
                        toInstant(rs.getTimestamp("run_started_at")),
                        toInstant(rs.getTimestamp("run_completed_at")),
                        rs.getObject("records_downloaded", Integer.class),
                        rs.getObject("records_processed", Integer.class),
                        rs.getObject("records_skipped", Integer.class),
                        rs.getObject("records_inserted", Integer.class),
                        rs.getObject("records_updated", Integer.class)
                )
        );
    }

    private Instant toInstant(Timestamp timestamp) {
        return timestamp == null ? null : timestamp.toInstant();
    }
}