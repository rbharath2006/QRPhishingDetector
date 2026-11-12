-- V4: Prepare the database for reusable feed ingestion.

ALTER TABLE feed_sync_run
    ADD COLUMN records_processed INTEGER NOT NULL DEFAULT 0
        CHECK (records_processed >= 0);

ALTER TABLE feed_sync_run
    ADD COLUMN records_skipped INTEGER NOT NULL DEFAULT 0
        CHECK (records_skipped >= 0);

ALTER TABLE threat_indicator
    ADD COLUMN last_seen_sync_run_id BIGINT
        REFERENCES feed_sync_run(id)
            ON DELETE SET NULL;

-- A dedicated source for synthetic development fixtures.
-- These entries are NOT real threat intelligence.
INSERT INTO feed_source (
    source_key,
    display_name,
    feed_type,
    enabled,
    refresh_interval_seconds,
    last_status
)
VALUES (
           'LOCAL_TEST',
           'Local Synthetic Test Feed',
           'PHISHING_URLS',
           TRUE,
           86400,
           'NEVER_RUN'
       )
    ON CONFLICT (source_key) DO NOTHING;