package com.bharath.qr_phishing_detector.detection;

import com.bharath.qr_phishing_detector.validation.URLNormalizationService;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Set;

@Service
public class URLHeuristicsService {

    private static final Pattern IPV4_PATTERN =
            Pattern.compile("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$");

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

    private static final Pattern ENCODED_SEQUENCE =
            Pattern.compile("%[0-9a-fA-F]{2}");

    public Analysis analyze(
            String input,
            URLNormalizationService.NormalizedUrl normalized
    ) {
        final URI uri;

        try {
            uri = new URI(input.trim());
        } catch (URISyntaxException ex) {
            // URLNormalizationService should have rejected this first.
            throw new IllegalArgumentException(
                    "Cannot analyse an invalid URL.", ex
            );
        }

        String hostname = normalized.hostname()
                .toLowerCase(Locale.ROOT);
        int score = 0;
        List<String> reasons = new ArrayList<>();

        if (isKnownShortener(hostname)) {
            score += 12;
            reasons.add(
                    "The hostname belongs to a known URL-shortening service. "
                            + "The final destination may be obscured (+12)."
            );
        }

        // Rule 1: User-information can disguise the actual hostname.
        if (uri.getRawUserInfo() != null) {
            score += 30;
            reasons.add(
                    "URL contains user-information before the hostname; " +
                            "this can disguise the actual destination (+30)."
            );
        }

        // Rule 2: An IP literal is a weak-to-moderate risk signal.
        if (isIpLiteral(hostname)) {
            score += 15;
            reasons.add(
                    "The hostname is an IP address rather than a DNS name (+15)."
            );
        }

        // Rule 3: Punycode can represent internationalised domain names.
        // It is a warning signal, not proof of malicious intent.
        String[] labels = hostname.split("\\.");

        for (String label : labels) {
            if (label.startsWith("xn--")) {
                score += 12;
                reasons.add(
                        "The hostname contains a punycode label; " +
                                "inspect it for possible Unicode lookalike characters (+12)."
                );
                break;
            }
        }

        // Rule 4: Deep hostname structures deserve closer inspection.
        if (labels.length >= 5) {
            score += 8;
            reasons.add(
                    "The hostname contains five or more labels; " +
                            "this is a weak contextual warning (+8)."
            );
        }

        // Rule 5: Non-standard ports may warrant additional inspection.
        int port = uri.getPort();
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);

        boolean nonDefaultPort = port != -1
                && !("http".equals(scheme) && port == 80)
                && !("https".equals(scheme) && port == 443);

        if (nonDefaultPort) {
            score += 8;
            reasons.add(
                    "The URL uses a non-default port (" + port +
                            "); this is not proof of phishing (+8)."
            );
        }

        // Rule 6: HTTP provides no transport encryption.
        if ("http".equals(scheme)) {
            score += 5;
            reasons.add(
                    "The URL uses HTTP instead of HTTPS; " +
                            "this is a limited warning, not proof of phishing (+5)."
            );
        }

        // Rule 7: Very long URLs can be harder for users to inspect.
        int length = input.trim().length();

        if (length >= 180) {
            score += 6;
            reasons.add(
                    "The URL is unusually long (180 or more characters) (+6)."
            );
        } else if (length >= 120) {
            score += 4;
            reasons.add(
                    "The URL is relatively long (120 or more characters) (+4)."
            );
        }

        // Rule 8: Excessive percent encoding can merit closer inspection.
        Matcher matcher = ENCODED_SEQUENCE.matcher(input);
        int encodedSequences = 0;

        while (matcher.find()) {
            encodedSequences++;
        }

        if (encodedSequences >= 5) {
            score += 5;
            reasons.add(
                    "The URL contains five or more percent-encoded sequences (+5)."
            );
        }

        return new Analysis(
                Math.min(score, 100),
                List.copyOf(reasons)
        );
    }

    private boolean isIpLiteral(String hostname) {
        // IPv6 literals contain colons. The normalizer removes URI brackets.
        if (hostname.contains(":")) {
            return true;
        }

        if (!IPV4_PATTERN.matcher(hostname).matches()) {
            return false;
        }

        String[] octets = hostname.split("\\.");

        for (String octet : octets) {
            try {
                int value = Integer.parseInt(octet);

                if (value < 0 || value > 255) {
                    return false;
                }
            } catch (NumberFormatException ex) {
                return false;
            }
        }

        return true;
    }

    private boolean isKnownShortener(String hostname) {
        for (String shortener : KNOWN_SHORTENERS) {
            if (hostname.equals(shortener)
                    || hostname.endsWith("." + shortener)) {
                return true;
            }
        }

        return false;
    }


    public record Analysis(
            int score,
            List<String> reasons
    ) {
    }
}