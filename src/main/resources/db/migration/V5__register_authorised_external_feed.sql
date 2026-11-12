-- V5: Register an external source without enabling downloads.

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
           'AUTHORISED_PHISHING_FEED',
           'Authorised External Phishing Feed',
           'PHISHING_URLS',
           NULL,
           FALSE,
           43200,
           'NEVER_RUN'
       )
    ON CONFLICT (source_key) DO NOTHING;