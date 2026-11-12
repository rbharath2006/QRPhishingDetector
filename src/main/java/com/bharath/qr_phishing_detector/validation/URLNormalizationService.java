package com.bharath.qr_phishing_detector.validation;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.net.IDN;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Locale;

@Service
public class URLNormalizationService {

    public NormalizedUrl normalize(String input) {

        if (input == null || input.isBlank()) {
            throw badRequest("URL is required.");
        }

        String raw = input.trim();

        if (raw.length() > 2048) {
            throw badRequest("URL must not exceed 2048 characters.");
        }

        for (int i = 0; i < raw.length(); i++) {
            if (Character.isISOControl(raw.charAt(i))) {
                throw badRequest("URL contains unsupported control characters.");
            }
        }

        final URI uri;

        try {
            uri = new URI(raw);
        } catch (URISyntaxException ex) {
            throw badRequest("URL format is invalid.");
        }

        String scheme = uri.getScheme();

        if (scheme == null
                || !(scheme.equalsIgnoreCase("http")
                || scheme.equalsIgnoreCase("https"))) {
            throw badRequest("Only HTTP and HTTPS URLs are supported.");
        }

        String originalHost = uri.getHost();

        if (originalHost == null || originalHost.isBlank()) {
            throw badRequest("A valid URL hostname is required.");
        }

        boolean ipv6 = originalHost.contains(":");
        String hostname;

        try {
            if (ipv6) {
                hostname = originalHost
                        .replace("[", "")
                        .replace("]", "")
                        .toLowerCase(Locale.ROOT);
            } else {
                hostname = IDN.toASCII(
                        originalHost,
                        IDN.USE_STD3_ASCII_RULES
                ).toLowerCase(Locale.ROOT);

                // A trailing DNS root dot is equivalent for hostname matching.
                if (hostname.endsWith(".")) {
                    hostname = hostname.substring(0, hostname.length() - 1);
                }
            }
        } catch (IllegalArgumentException ex) {
            throw badRequest("URL hostname is invalid.");
        }

        if (hostname.isBlank()) {
            throw badRequest("A valid URL hostname is required.");
        }

        int port = uri.getPort();

        if (port == 0 || port > 65535) {
            throw badRequest("URL port is outside the allowed range.");
        }

        String normalizedScheme = scheme.toLowerCase(Locale.ROOT);
        String authorityHost = ipv6 ? "[" + hostname + "]" : hostname;

        StringBuilder canonical = new StringBuilder();
        canonical.append(normalizedScheme).append("://");

        // Preserve user-info for exact indicator matching. The parsed hostname
        // still comes from URI.getHost(), not from text before the @ character.
        if (uri.getRawUserInfo() != null) {
            canonical.append(uri.getRawUserInfo()).append("@");
        }

        canonical.append(authorityHost);

        boolean defaultPort =
                (normalizedScheme.equals("http") && port == 80)
                        || (normalizedScheme.equals("https") && port == 443);

        if (port != -1 && !defaultPort) {
            canonical.append(":").append(port);
        }

        URI normalizedUri = uri.normalize();
        String path = normalizedUri.getRawPath();

        canonical.append(
                path == null || path.isEmpty() ? "/" : path
        );

        if (normalizedUri.getRawQuery() != null) {
            canonical.append("?").append(normalizedUri.getRawQuery());
        }

        // Fragments are omitted because browsers do not send them to the server.
        return new NormalizedUrl(canonical.toString(), hostname);
    }

    public String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(
                    value.getBytes(StandardCharsets.UTF_8)
            );

            return HexFormat.of().formatHex(bytes);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(
                    "SHA-256 is unavailable in this Java runtime.",
                    ex
            );
        }
    }

    private ResponseStatusException badRequest(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }

    public record NormalizedUrl(
            String canonicalUrl,
            String hostname
    ) {
    }
}