package com.bharath.qr_phishing_detector.ingestion;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RemoteTextFeedClientTest {

    private final RemoteTextFeedClient client =
            new RemoteTextFeedClient(new UrlLineFeedParser());

    @Test
    void rejectsHttpFeeds() {
        assertThrows(
                IllegalArgumentException.class,
                () -> client.fetchAndParse(
                        "http://feeds.example.org/list.txt",
                        "feeds.example.org"
                )
        );
    }

    @Test
    void rejectsHostnameNotOnAllowlist() {
        assertThrows(
                IllegalArgumentException.class,
                () -> client.fetchAndParse(
                        "https://feeds.example.org/list.txt",
                        "another.example.org"
                )
        );
    }

    @Test
    void rejectsLocalhost() {
        assertThrows(
                IllegalArgumentException.class,
                () -> client.fetchAndParse(
                        "https://localhost/list.txt",
                        "localhost"
                )
        );
    }

    @Test
    void rejectsUrlsContainingUserInformation() {
        assertThrows(
                IllegalArgumentException.class,
                () -> client.fetchAndParse(
                        "https://user@feeds.example.org/list.txt",
                        "feeds.example.org"
                )
        );
    }
}