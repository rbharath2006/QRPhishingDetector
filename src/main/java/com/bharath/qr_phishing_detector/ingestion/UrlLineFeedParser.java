package com.bharath.qr_phishing_detector.ingestion;

import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.List;

@Component
public class UrlLineFeedParser {

    private static final int MAX_ENTRIES = 50_000;
    private static final int MAX_LINE_LENGTH = 4096;

    /**
     * Parses a text feed containing one indicator per line.
     *
     * Blank lines and lines starting with # are ignored.
     * URL validation and deduplication are performed by the ingestion service.
     *
     * The caller owns the Reader and is responsible for closing it.
     */
    public List<String> parse(Reader input) throws IOException {

        if (input == null) {
            throw new IllegalArgumentException(
                    "Feed reader must not be null."
            );
        }

        BufferedReader reader = input instanceof BufferedReader buffered
                ? buffered
                : new BufferedReader(input);

        List<String> entries = new ArrayList<>();
        String line;
        int lineNumber = 0;

        while ((line = reader.readLine()) != null) {
            lineNumber++;

            if (line.length() > MAX_LINE_LENGTH) {
                throw new IOException(
                        "Feed line " + lineNumber
                                + " exceeds the permitted length."
                );
            }

            // Remove a UTF-8 BOM if it appears at the beginning of the file.
            if (lineNumber == 1 && !line.isEmpty()
                    && line.charAt(0) == '\uFEFF') {
                line = line.substring(1);
            }

            String value = line.trim();

            if (value.isEmpty() || value.startsWith("#")) {
                continue;
            }

            if (entries.size() >= MAX_ENTRIES) {
                throw new IOException(
                        "Feed exceeds the maximum permitted entry count."
                );
            }

            entries.add(value);
        }

        return List.copyOf(entries);
    }
}