-- V3: Align the hash column with the Java entity mapping.

ALTER TABLE threat_indicator
ALTER COLUMN normalized_value_hash
TYPE VARCHAR(64)
USING BTRIM(normalized_value_hash)::VARCHAR(64);