INSERT INTO feed_source (
    source_key,
    display_name,
    feed_type,
    enabled,
    refresh_interval_seconds,
    last_status
)
VALUES
    ('LOCAL_MANUAL', 'Local Manual Indicators',
     'MIXED', TRUE, 86400, 'NEVER_RUN'),

    ('PHISHTANK', 'PhishTank',
     'PHISHING_URLS', FALSE, 3600, 'NEVER_RUN'),

    ('URLHAUS', 'URLhaus',
     'MALWARE_URLS', FALSE, 300, 'NEVER_RUN')

    ON CONFLICT (source_key) DO NOTHING;