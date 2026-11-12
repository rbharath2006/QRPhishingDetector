package com.bharath.qr_phishing_detector.ingestion;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.StringReader;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class UrlLineFeedParserTest {

    private final UrlLineFeedParser parser =
            new UrlLineFeedParser();

    @Test
    void ignoresBlankLinesAndComments() throws IOException {
        String input = """
                # Synthetic test feed

                https://alpha.demo.test/login

                # Another comment
                https://beta.demo.test/account
                """;

        assertEquals(
                List.of(
                        "https://alpha.demo.test/login",
                        "https://beta.demo.test/account"
                ),
                parser.parse(new StringReader(input))
        );
    }

    @Test
    void trimsEntriesAndHandlesBom() throws IOException {
        String input =
                "\uFEFF  https://alpha.demo.test/login  \n";

        assertEquals(
                List.of("https://alpha.demo.test/login"),
                parser.parse(new StringReader(input))
        );
    }

    @Test
    void retainsDuplicateEntriesForIngestionLayer() throws IOException {
        String url = "https://alpha.demo.test/login";

        assertEquals(
                List.of(url, url),
                parser.parse(new StringReader(url + "\n" + url))
        );
    }

    @Test
    void returnsEmptyListForCommentOnlyFeed() throws IOException {
        assertTrue(
                parser.parse(
                        new StringReader("# No entries\n\n")
                ).isEmpty()
        );
    }

    @Test
    void rejectsExcessivelyLongLine() {
        String input = "a".repeat(4097);

        assertThrows(
                IOException.class,
                () -> parser.parse(new StringReader(input))
        );
    }

    @Test
    void rejectsMoreThanMaximumEntries() {
        String input = "https://alpha.demo.test/login\n"
                .repeat(50_001);

        assertThrows(
                IOException.class,
                () -> parser.parse(new StringReader(input))
        );
    }
}