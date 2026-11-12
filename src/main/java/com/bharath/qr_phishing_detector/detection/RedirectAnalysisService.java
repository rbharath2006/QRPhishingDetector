package com.bharath.qr_phishing_detector.detection;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Arrays;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@Service
public class RedirectAnalysisService {

    private static final int MAX_HOPS = 5;

    private static final Set<String> KNOWN_SHORTENERS = Set.of(
            "bit.ly",
            "tinyurl.com",
            "t.co",
            "is.gd",
            "cutt.ly",
            "shorturl.at",
            "ow.ly",
            "buff.ly",
            "rebrand.ly",
            "lnkd.in",
            "rb.gy",
            "tiny.cc",
            "soo.gd"
    );

    private final HttpClient httpClient;
    private final HostAddressResolver hostAddressResolver;

    @FunctionalInterface
    interface HostAddressResolver {
        InetAddress[] resolve(String hostname) throws IOException;
    }

    @Autowired
    public RedirectAnalysisService() {
        this(createHttpClient(), InetAddress::getAllByName);
    }

    // Existing test constructor, retained for compatibility.
    RedirectAnalysisService(HttpClient httpClient) {
        this(httpClient, InetAddress::getAllByName);
    }

    // Injectable resolver lets tests use deterministic, offline addresses.
    RedirectAnalysisService(
            HttpClient httpClient,
            HostAddressResolver hostAddressResolver
    ) {
        this.httpClient = httpClient;
        this.hostAddressResolver = hostAddressResolver;
    }

    private static HttpClient createHttpClient() {
        return HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    /**
     * Resolves redirect headers from known shortening services only.
     * It never requests a redirect destination unless that destination
     * is itself an explicitly allowlisted HTTPS shortener.
     */
    public Resolution resolve(String submittedUrl)
            throws IOException, InterruptedException {

        URI current = validateShortenerUrl(submittedUrl);

        String originalUrl = current.toASCIIString();
        List<String> chain = new ArrayList<>();
        Set<String> visited = new HashSet<>();

        chain.add(originalUrl);

        for (int hop = 0; hop < MAX_HOPS; hop++) {

            String currentKey = current.toASCIIString();

            if (!visited.add(currentKey)) {
                return new Resolution(
                        "LOOP_DETECTED",
                        originalUrl,
                        List.copyOf(chain),
                        null,
                        hop,
                        "A redirect loop was detected."
                );
            }
            // DNS defense in depth: refuse requests if any returned address
// is private, local, or in a common reserved range.
            if (resolvesToNonPublicAddress(current.getHost())) {
                return new Resolution(
                        "BLOCKED_NON_PUBLIC_ADDRESS",
                        originalUrl,
                        List.copyOf(chain),
                        null,
                        hop,
                        "The approved shortener hostname resolved to a non-public "
                                + "or reserved IP address. No request was sent."
                );
            }
            HttpRequest request = HttpRequest.newBuilder(current)
                    .timeout(Duration.ofSeconds(8))
                    .header("User-Agent", "QRPhishingDetector/1.0")
                    .header("Accept", "*/*")
                    .header("Range", "bytes=0-0")
                    .GET()
                    .build();

            HttpResponse<InputStream> response =
                    httpClient.send(
                            request,
                            HttpResponse.BodyHandlers.ofInputStream()
                    );

            int status;

            String location;

            try (InputStream body = response.body()) {
                status = response.statusCode();
                location = response.headers()
                        .firstValue("Location")
                        .orElse(null);
                // We inspect response headers only; the body is not read.
            }

            if (status >= 300 && status < 400) {

                if (location == null || location.isBlank()) {
                    return new Resolution(
                            "REDIRECT_WITHOUT_LOCATION",
                            originalUrl,
                            List.copyOf(chain),
                            null,
                            hop + 1,
                            "The service returned a redirect without a destination."
                    );
                }

                final URI next;

                try {
                    URI locationUri = new URI(location.trim());
                    next = current.resolve(locationUri).normalize();
                } catch (URISyntaxException | IllegalArgumentException ex) {
                    return new Resolution(
                            "INVALID_REDIRECT_LOCATION",
                            originalUrl,
                            List.copyOf(chain),
                            null,
                            hop + 1,
                            "The service returned an invalid redirect destination."
                    );
                }

                String scheme = next.getScheme();

                if (scheme == null
                        || !(scheme.equalsIgnoreCase("http")
                        || scheme.equalsIgnoreCase("https"))) {

                    return new Resolution(
                            "UNSUPPORTED_REDIRECT_SCHEME",
                            originalUrl,
                            List.copyOf(chain),
                            null,
                            hop + 1,
                            "The redirect used a scheme that this resolver does not support."
                    );
                }
                // Reject malformed web destinations and URLs containing credentials.
// The resolver must not treat these as successfully revealed destinations.
                if (next.getHost() == null
                        || next.getRawUserInfo() != null
                        || next.getPort() == 0
                        || next.getPort() > 65535) {

                    return new Resolution(
                            "INVALID_REDIRECT_LOCATION",
                            originalUrl,
                            List.copyOf(chain),
                            null,
                            hop + 1,
                            "The redirect target does not contain a valid web host."
                    );
                }

                String destination = next.toASCIIString();
                chain.add(destination);

                // Continue only if the next target is another known
                // HTTPS shortener. Never fetch an arbitrary destination.
                if (isAllowedShortener(next)) {
                    current = next;
                    continue;
                }

                return new Resolution(
                        "DESTINATION_REVEALED",
                        originalUrl,
                        List.copyOf(chain),
                        destination,
                        hop + 1,
                        "The redirect destination was identified but was not opened or fetched."
                );
            }

            if (status >= 400) {
                return new Resolution(
                        "UPSTREAM_ERROR",
                        originalUrl,
                        List.copyOf(chain),
                        null,
                        hop + 1,
                        "The URL-shortening service returned HTTP " + status + "."
                );
            }

            return new Resolution(
                    "NO_REDIRECT_FOUND",
                    originalUrl,
                    List.copyOf(chain),
                    null,
                    hop + 1,
                    "The service did not provide a redirect destination."
            );
        }

        return new Resolution(
                "MAX_HOPS_REACHED",
                originalUrl,
                List.copyOf(chain),
                null,
                MAX_HOPS,
                "The maximum number of redirect hops was reached."
        );
    }
    private boolean resolvesToNonPublicAddress(String hostname)
            throws IOException {


        InetAddress[] addresses;

        try {
            addresses = hostAddressResolver.resolve(hostname);
        } catch (IOException ex) {
            // Fail closed: if DNS resolution fails, block the request.
            return true;
        }


        // Fail closed if DNS returned no usable addresses.
        if (addresses == null || addresses.length == 0) {
            return true;
        }

        // Reject the hostname if ANY resolved address is non-public
        // or falls into one of the blocked ranges below.
        for (InetAddress address : addresses) {
            if (address == null || isNonPublicOrSpecialUse(address)) {
                return true;
            }
        }

        return false;
    }

    private static boolean isNonPublicOrSpecialUse(InetAddress address) {

        if (address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress()) {
            return true;
        }

        byte[] bytes = address.getAddress();

        if (address instanceof Inet4Address) {
            return isNonPublicIpv4(bytes);
        }

        if (address instanceof Inet6Address) {

            // IPv6 unique-local addresses: fc00::/7.
            if ((bytes[0] & 0xFE) == 0xFC) {
                return true;
            }

            // IPv6 documentation addresses: 2001:db8::/32.
            if ((bytes[0] & 0xFF) == 0x20
                    && (bytes[1] & 0xFF) == 0x01
                    && (bytes[2] & 0xFF) == 0x0D
                    && (bytes[3] & 0xFF) == 0xB8) {
                return true;
            }

            // Conservatively block IPv6 6to4 and Teredo transition ranges.
            if ((bytes[0] & 0xFF) == 0x20
                    && (bytes[1] & 0xFF) == 0x02) {
                return true;
            }

            if ((bytes[0] & 0xFF) == 0x20
                    && (bytes[1] & 0xFF) == 0x01
                    && bytes[2] == 0
                    && bytes[3] == 0) {
                return true;
            }

            // IPv4-mapped IPv6 addresses must be checked as IPv4 too.
            boolean ipv4Mapped = true;

            for (int i = 0; i < 10; i++) {
                if (bytes[i] != 0) {
                    ipv4Mapped = false;
                    break;
                }
            }

            if (ipv4Mapped
                    && (bytes[10] & 0xFF) == 0xFF
                    && (bytes[11] & 0xFF) == 0xFF) {

                return isNonPublicIpv4(Arrays.copyOfRange(bytes, 12, 16));
            }
        }

        return false;
    }

    private static boolean isNonPublicIpv4(byte[] bytes) {

        int a = bytes[0] & 0xFF;
        int b = bytes[1] & 0xFF;
        int c = bytes[2] & 0xFF;

        // 0.0.0.0/8.
        if (a == 0) {
            return true;
        }

        // 100.64.0.0/10: carrier-grade NAT.
        if (a == 100 && b >= 64 && b <= 127) {
            return true;
        }

        // 192.0.0.0/24 and 192.0.2.0/24.
        if (a == 192 && b == 0 && (c == 0 || c == 2)) {
            return true;
        }

        // 198.18.0.0/15: benchmarking.
        if (a == 198 && (b == 18 || b == 19)) {
            return true;
        }

        // Documentation ranges.
        if (a == 198 && b == 51 && c == 100) {
            return true;
        }

        if (a == 203 && b == 0 && c == 113) {
            return true;
        }

        // 240.0.0.0/4: reserved address space.
        if (a >= 240) {
            return true;
        }

        // The earlier InetAddress checks cover standard private,
        // loopback, link-local, and multicast ranges.
        return false;
    }

    private URI validateShortenerUrl(String input) {

        if (input == null || input.isBlank() || input.length() > 2048) {
            throw new IllegalArgumentException(
                    "A URL of at most 2048 characters is required."
            );
        }

        for (int i = 0; i < input.length(); i++) {
            if (Character.isISOControl(input.charAt(i))) {
                throw new IllegalArgumentException(
                        "The URL contains unsupported control characters."
                );
            }
        }

        final URI uri;

        try {
            uri = new URI(input.trim()).normalize();
        } catch (URISyntaxException ex) {
            throw new IllegalArgumentException("The URL is invalid.");
        }

        if (!isAllowedShortener(uri)) {
            throw new IllegalArgumentException(
                    "Only HTTPS URLs from the configured shortener allowlist can be resolved."
            );
        }

        return uri;
    }

    private boolean isAllowedShortener(URI uri) {

        if (uri == null
                || uri.getScheme() == null
                || !uri.getScheme().equalsIgnoreCase("https")
                || uri.getHost() == null
                || uri.getRawUserInfo() != null
                || uri.getRawFragment() != null
                || (uri.getPort() != -1 && uri.getPort() != 443)) {
            return false;
        }

        String hostname = uri.getHost()
                .toLowerCase(Locale.ROOT);

        if (hostname.endsWith(".")) {
            hostname = hostname.substring(0, hostname.length() - 1);
        }

        return KNOWN_SHORTENERS.contains(hostname);
    }

    public record Resolution(
            String status,
            String originalUrl,
            List<String> redirectChain,
            String destination,
            int requestsMade,
            String message
    ) {
    }
}