package com.bharath.qr_phishing_detector.ingestion;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;


@Component
@ConditionalOnProperty(
        prefix = "app.feeds.local-test",
        name = "run-on-startup",
        havingValue = "true"
)
public class LocalTestFeedRunner implements ApplicationRunner {

    private static final Logger log =
            LoggerFactory.getLogger(LocalTestFeedRunner.class);

    private static final long MAX_FILE_BYTES = 1024 * 1024;
    private final UrlLineFeedParser feedParser;

    private final ThreatFeedIngestionService ingestionService;

    @Value("${app.feeds.local-test.file:./dev-data/local-phishing-urls.txt}")
    private String feedFile;

    public LocalTestFeedRunner(
            ThreatFeedIngestionService ingestionService,
            UrlLineFeedParser feedParser
    ) {
        this.ingestionService = ingestionService;
        this.feedParser = feedParser;
    }

    @Override
    public void run(ApplicationArguments args) {

        try {
            Path path = Path.of(feedFile)
                    .toAbsolutePath()
                    .normalize();

            if (!Files.isRegularFile(path)) {
                log.error(
                        "Local feed import skipped: configured file does not exist."
                );
                return;
            }

            if (Files.size(path) > MAX_FILE_BYTES) {
                log.error(
                        "Local feed import skipped: file exceeds the 1 MB limit."
                );
                return;
            }

            List<String> urls;

            try (var reader = Files.newBufferedReader(
                    path,
                    StandardCharsets.UTF_8
            )) {
                urls = feedParser.parse(reader);
            }

            ThreatFeedIngestionService.ImportSummary summary =
                    ingestionService.ingestUrlSnapshot("LOCAL_TEST", urls);

            log.info(
                    "Local test import completed: runId={}, processed={}, " +
                            "skipped={}, inserted={}, updated={}",
                    summary.syncRunId(),
                    summary.recordsProcessed(),
                    summary.recordsSkipped(),
                    summary.recordsInserted(),
                    summary.recordsUpdated()
            );

        } catch (IOException ex) {
            log.error(
                    "Local feed import failed because the file could not be read. " +
                            "The application will continue running.",
                    ex
            );

        } catch (RuntimeException ex) {
            log.error(
                    "Local feed import failed ({}). " +
                            "The application will continue running.",
                    ex.getClass().getSimpleName()
            );
        }
    }
}