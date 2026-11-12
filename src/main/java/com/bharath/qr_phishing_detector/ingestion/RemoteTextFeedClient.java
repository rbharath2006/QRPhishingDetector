package com.bharath.qr_phishing_detector.ingestion;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Locale;

@Service
public class RemoteTextFeedClient {

    private static final int MAX_RESPONSE_BYTES = 10 * 1024 * 1024;

    private final UrlLineFeedParser parser;
    private final HttpClient httpClient;

    @Autowired
    public RemoteTextFeedClient(UrlLineFeedParser parser) {
        this(parser, createHttpClient());
    }

    RemoteTextFeedClient(
            UrlLineFeedParser parser,
            HttpClient httpClient
    ) {
        this.parser = parser;
        this.httpClient = httpClient;
    }

    private static HttpClient createHttpClient() {
        return HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    public List<String> fetchAndParse(
            String feedUrl,
            String allowedHost
    ) throws IOException, InterruptedException {

        URI uri = validateRemoteFeedUri(feedUrl, allowedHost);

        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(30))
                .header("User-Agent", "QRPhishingDetector/1.0")
                .header("Accept", "text/plain")
                .header("Accept-Encoding", "identity")
                .GET()
                .build();

        HttpResponse<InputStream> response = httpClient.send(
                request,
                HttpResponse.BodyHandlers.ofInputStream()
        );

        try (InputStream body = response.body()) {

            if (response.statusCode() != 200) {
                throw new IOException(
                        "Remote feed returned HTTP status "
                                + response.statusCode()
                );
            }

            long contentLength = response.headers()
                    .firstValueAsLong("Content-Length")
                    .orElse(-1L);

            if (contentLength > MAX_RESPONSE_BYTES) {
                throw new IOException(
                        "Remote feed exceeds the permitted download size."
                );
            }

            byte[] bytes = body.readNBytes(MAX_RESPONSE_BYTES + 1);

            if (bytes.length > MAX_RESPONSE_BYTES) {
                throw new IOException(
                        "Remote feed exceeds the permitted download size."
                );
            }

            String contents;

            try {
                contents = StandardCharsets.UTF_8
                        .newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(bytes))
                        .toString();
            } catch (CharacterCodingException ex) {
                throw new IOException(
                        "Remote feed is not valid UTF-8 text."
                );
            }

            return parser.parse(new StringReader(contents));
        }
    }

    private URI validateRemoteFeedUri(
            String feedUrl,
            String allowedHost
    ) {

        if (feedUrl == null || feedUrl.isBlank()) {
            throw new IllegalArgumentException(
                    "Remote feed URL is not configured."
            );
        }

        if (allowedHost == null || allowedHost.isBlank()) {
            throw new IllegalArgumentException(
                    "Remote feed hostname allowlist is not configured."
            );
        }

        final URI uri;

        try {
            uri = new URI(feedUrl.trim());
        } catch (URISyntaxException ex) {
            throw new IllegalArgumentException(
                    "Remote feed URL is invalid."
            );
        }

        if (!"https".equalsIgnoreCase(uri.getScheme())
                || uri.getHost() == null
                || uri.getUserInfo() != null
                || uri.getFragment() != null
                || (uri.getPort() != -1 && uri.getPort() != 443)) {

            throw new IllegalArgumentException(
                    "Remote feed must use a valid HTTPS URL."
            );
        }

        String host = uri.getHost()
                .toLowerCase(Locale.ROOT);

        String permittedHost = allowedHost.trim()
                .toLowerCase(Locale.ROOT);

        if (permittedHost.endsWith(".")) {
            permittedHost = permittedHost.substring(
                    0, permittedHost.length() - 1
            );
        }

        if (!host.equals(permittedHost)) {
            throw new IllegalArgumentException(
                    "Remote feed hostname does not match the configured allowlist."
            );
        }

        if (host.equals("localhost")
                || host.endsWith(".localhost")
                || host.endsWith(".local")
                || host.endsWith(".test")
                || host.endsWith(".internal")
                || host.matches("[0-9.]+")
                || host.contains(":")
                || !host.contains(".")) {

            throw new IllegalArgumentException(
                    "Local, test, or literal IP hosts are not permitted."
            );
        }

        return uri;
    }
}