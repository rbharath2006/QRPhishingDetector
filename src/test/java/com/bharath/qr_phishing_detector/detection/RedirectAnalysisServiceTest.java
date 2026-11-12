package com.bharath.qr_phishing_detector.detection;
import java.io.IOException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import java.net.InetAddress;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RedirectAnalysisServiceTest {

    @Mock
    private HttpClient httpClient;

    private RedirectAnalysisService service;

    @BeforeEach
    void setUp() {
        service = new RedirectAnalysisService(
                httpClient,
                hostname -> new InetAddress[]{
                        InetAddress.getByAddress(
                                new byte[]{8, 8, 8, 8}
                        )
                }
        );
    }

    @Test
    void revealsDestinationWithoutFetchingIt() throws Exception {

        // Prepare the response BEFORE starting Mockito stubbing.
        HttpResponse<InputStream> redirectResponse =
                response(302, "https://example.com/login");

        when(httpClient.send(
                ArgumentMatchers.any(HttpRequest.class),
                ArgumentMatchers
                        .<HttpResponse.BodyHandler<InputStream>>any()
        )).thenReturn(redirectResponse);

        RedirectAnalysisService.Resolution result =
                service.resolve("https://bit.ly/example123");

        assertEquals(
                "DESTINATION_REVEALED",
                String.valueOf(result.status())
        );

        assertEquals(
                "https://example.com/login",
                result.destination()
        );

        assertEquals(1, result.requestsMade());

        // The destination site itself must not be fetched.
        verify(httpClient, times(1)).send(
                ArgumentMatchers.any(HttpRequest.class),
                ArgumentMatchers
                        .<HttpResponse.BodyHandler<InputStream>>any()
        );
    }

    @Test
    void closesResponseBodyWithoutReadingIt() throws Exception {
        AtomicBoolean bodyClosed = new AtomicBoolean(false);

        InputStream trackingBody = new InputStream() {
            @Override
            public int read() {
                throw new AssertionError(
                        "The redirect analyzer must not read the response body."
                );
            }

            @Override
            public void close() {
                bodyClosed.set(true);
            }
        };

        @SuppressWarnings("unchecked")
        HttpResponse<InputStream> redirectResponse =
                (HttpResponse<InputStream>) mock(HttpResponse.class);

        when(redirectResponse.statusCode()).thenReturn(302);

        when(redirectResponse.headers()).thenReturn(
                HttpHeaders.of(
                        Map.of("Location", List.of("https://example.com/login")),
                        (name, value) -> true
                )
        );

        when(redirectResponse.body()).thenReturn(trackingBody);

        when(httpClient.send(
                ArgumentMatchers.any(HttpRequest.class),
                ArgumentMatchers.<HttpResponse.BodyHandler<InputStream>>any()
        )).thenReturn(redirectResponse);

        RedirectAnalysisService.Resolution result =
                service.resolve("https://bit.ly/example123");

        assertEquals("DESTINATION_REVEALED", String.valueOf(result.status()));
        assertEquals("https://example.com/login", result.destination());
        assertTrue(bodyClosed.get(), "The response body should be closed.");
    }


    @Test
    void followsAnotherKnownShortenerButNotTheFinalSite()
            throws Exception {

        // Create both responses before stubbing the HTTP client.
        HttpResponse<InputStream> firstResponse =
                response(302, "https://tinyurl.com/second123");

        HttpResponse<InputStream> secondResponse =
                response(302, "https://example.com/login");

        when(httpClient.send(
                ArgumentMatchers.any(HttpRequest.class),
                ArgumentMatchers
                        .<HttpResponse.BodyHandler<InputStream>>any()
        )).thenReturn(firstResponse, secondResponse);

        RedirectAnalysisService.Resolution result =
                service.resolve("https://bit.ly/first123");

        assertEquals(
                "DESTINATION_REVEALED",
                String.valueOf(result.status())
        );

        assertEquals(
                "https://example.com/login",
                result.destination()
        );

        assertEquals(2, result.requestsMade());

        // Only the two shortener URLs should be requested.
        verify(httpClient, times(2)).send(
                ArgumentMatchers.any(HttpRequest.class),
                ArgumentMatchers
                        .<HttpResponse.BodyHandler<InputStream>>any()
        );
    }

    @Test
    void rejectsOrdinaryWebsite() {

        assertThrows(
                IllegalArgumentException.class,
                () -> service.resolve("https://example.com/login")
        );

        verifyNoInteractions(httpClient);
    }

    @Test
    void rejectsHttpShortener() {

        assertThrows(
                IllegalArgumentException.class,
                () -> service.resolve("http://bit.ly/example123")
        );

        verifyNoInteractions(httpClient);
    }

    @Test
    void rejectsUserInfoInUrl() {

        assertThrows(
                IllegalArgumentException.class,
                () -> service.resolve(
                        "https://attacker@bit.ly/example123"
                )
        );

        verifyNoInteractions(httpClient);
    }

    @Test
    void reportsUpstreamError() throws Exception {

        // Prepare the response first.
        HttpResponse<InputStream> errorResponse =
                response(503, null);

        when(httpClient.send(
                ArgumentMatchers.any(HttpRequest.class),
                ArgumentMatchers
                        .<HttpResponse.BodyHandler<InputStream>>any()
        )).thenReturn(errorResponse);

        RedirectAnalysisService.Resolution result =
                service.resolve("https://bit.ly/example123");

        assertEquals(
                "UPSTREAM_ERROR",
                String.valueOf(result.status())
        );

        assertEquals(1, result.requestsMade());
        assertNotNull(result.message());
    }

    @Test
    void stopsRedirectLoop() throws Exception {

        // First redirect points to another approved shortener.
        HttpResponse<InputStream> firstResponse =
                response(302, "https://tinyurl.com/loop123");

        // The second response points back to the original URL.
        HttpResponse<InputStream> secondResponse =
                response(302, "https://bit.ly/loop123");

        when(httpClient.send(
                ArgumentMatchers.any(HttpRequest.class),
                ArgumentMatchers
                        .<HttpResponse.BodyHandler<InputStream>>any()
        )).thenReturn(firstResponse, secondResponse);

        RedirectAnalysisService.Resolution result =
                service.resolve("https://bit.ly/loop123");

        assertEquals(
                "LOOP_DETECTED",
                String.valueOf(result.status())
        );

        assertEquals(2, result.requestsMade());
    }
    @Test
    void rejectsLookalikeShortenerHostname() {
        assertThrows(
                IllegalArgumentException.class,
                () -> service.resolve(
                        "https://bit.ly.attacker.example/payload"
                )
        );

        verifyNoInteractions(httpClient);
    }

    @Test
    void rejectsNonStandardPort() {
        assertThrows(
                IllegalArgumentException.class,
                () -> service.resolve(
                        "https://bit.ly:8443/payload"
                )
        );

        verifyNoInteractions(httpClient);
    }

    @Test
    void rejectsRedirectLocationWithoutHost() throws Exception {
        HttpResponse<InputStream> redirectResponse =
                response(302, "https:///example.com/login");

        when(httpClient.send(
                ArgumentMatchers.any(HttpRequest.class),
                ArgumentMatchers
                        .<HttpResponse.BodyHandler<InputStream>>any()
        )).thenReturn(redirectResponse);

        RedirectAnalysisService.Resolution result =
                service.resolve("https://bit.ly/example123");

        assertEquals(
                "INVALID_REDIRECT_LOCATION",
                result.status()
        );

        assertEquals(1, result.requestsMade());
    }

    @Test
    void rejectsRedirectLocationContainingUserInfo() throws Exception {
        HttpResponse<InputStream> redirectResponse =
                response(302, "https://user@example.com/login");

        when(httpClient.send(
                ArgumentMatchers.any(HttpRequest.class),
                ArgumentMatchers
                        .<HttpResponse.BodyHandler<InputStream>>any()
        )).thenReturn(redirectResponse);

        RedirectAnalysisService.Resolution result =
                service.resolve("https://bit.ly/example123");

        assertEquals(
                "INVALID_REDIRECT_LOCATION",
                result.status()
        );

        assertEquals(1, result.requestsMade());
    }


    @Test
    void blocksPrivateDnsAddressBeforeSendingRequest() throws Exception {

        service = new RedirectAnalysisService(
                httpClient,
                hostname -> new InetAddress[]{
                        InetAddress.getByAddress(
                                new byte[]{10, 0, 0, 5}
                        )
                }
        );

        RedirectAnalysisService.Resolution result =
                service.resolve("https://bit.ly/example123");

        assertEquals(
                "BLOCKED_NON_PUBLIC_ADDRESS",
                result.status()
        );

        assertEquals(0, result.requestsMade());

        // A blocked address must never reach the HTTP client.
        verifyNoInteractions(httpClient);
    }

    @Test
    void blocksHostnameIfAnyDnsAnswerIsNonPublic() throws Exception {

        service = new RedirectAnalysisService(
                httpClient,
                hostname -> new InetAddress[]{
                        InetAddress.getByAddress(
                                new byte[]{8, 8, 8, 8}
                        ),
                        InetAddress.getByAddress(
                                new byte[]{10, 0, 0, 5}
                        )
                }
        );

        RedirectAnalysisService.Resolution result =
                service.resolve("https://bit.ly/example123");

        assertEquals(
                "BLOCKED_NON_PUBLIC_ADDRESS",
                result.status()
        );

        assertEquals(0, result.requestsMade());
        verifyNoInteractions(httpClient);
    }


    @Test
    void blocksRequestWhenDnsResolutionFails() throws Exception {
        service = new RedirectAnalysisService(httpClient, hostname -> {
            throw new IOException("Simulated DNS lookup failure");
        });

        RedirectAnalysisService.Resolution result =
                service.resolve("https://bit.ly/example123");

        assertEquals(
                "BLOCKED_NON_PUBLIC_ADDRESS",
                String.valueOf(result.status())
        );

        assertEquals(0, result.requestsMade());

        verifyNoInteractions(httpClient);
    }


    /*
     * Helper method to prepare a mocked HTTP response.
     *
     * Important:
     * Call this helper BEFORE using the response in thenReturn().
     */
    private HttpResponse<InputStream> response(
            int status,
            String location
    ) {

        @SuppressWarnings("unchecked")
        HttpResponse<InputStream> mockedResponse =
                (HttpResponse<InputStream>) mock(HttpResponse.class);

        when(mockedResponse.statusCode()).thenReturn(status);

        Map<String, List<String>> headers;

        if (location == null) {
            headers = Map.of();
        } else {
            headers = Map.of(
                    "Location",
                    List.of(location)
            );
        }

        HttpHeaders httpHeaders = HttpHeaders.of(
                headers,
                (name, value) -> true
        );

        when(mockedResponse.headers()).thenReturn(httpHeaders);

        when(mockedResponse.body()).thenReturn(
                new ByteArrayInputStream(new byte[0])
        );

        return mockedResponse;
    }
}