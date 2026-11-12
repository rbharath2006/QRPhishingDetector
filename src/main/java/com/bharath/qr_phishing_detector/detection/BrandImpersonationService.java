package com.bharath.qr_phishing_detector.detection;

import com.bharath.qr_phishing_detector.validation.RegistrableDomainService;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public class BrandImpersonationService {

    private static final Map<String, String> KNOWN_BRANDS = Map.ofEntries(
            Map.entry("paypal", "paypal.com"),
            Map.entry("google", "google.com"),
            Map.entry("microsoft", "microsoft.com"),
            Map.entry("apple", "apple.com"),
            Map.entry("amazon", "amazon.com"),
            Map.entry("facebook", "facebook.com"),
            Map.entry("instagram", "instagram.com"),
            Map.entry("netflix", "netflix.com"),
            Map.entry("linkedin", "linkedin.com"),
            Map.entry("github", "github.com"),
            Map.entry("dropbox", "dropbox.com")
    );

    private final RegistrableDomainService domainService;

    public BrandImpersonationService(
            RegistrableDomainService domainService
    ) {
        this.domainService = domainService;
    }

    public Analysis analyze(String hostname) {

        String registrableDomain = domainService
                .findRegistrableDomain(hostname)
                .orElse(null);

        if (registrableDomain == null) {
            return new Analysis(0, List.of());
        }

        String domainLabel = registrableDomain
                .substring(0, registrableDomain.indexOf('.'));

        String normalizedLabel = normalizeLookalikes(domainLabel);

        for (Map.Entry<String, String> entry
                : KNOWN_BRANDS.entrySet()) {

            String brand = entry.getKey();
            String officialDomain = entry.getValue();

            // Do not flag the exact listed domain or an exact brand label.
            // Exact-label domains may legitimately use other country suffixes.
            if (registrableDomain.equals(officialDomain)
                    || domainLabel.equals(brand)) {
                continue;
            }

            // Catch digit substitutions such as paypa1.com.
            if (normalizedLabel.equals(brand)) {
                return new Analysis(
                        35,
                        List.of(
                                "The registrable domain '" + registrableDomain
                                        + "' resembles the brand '" + brand
                                        + "' after common lookalike-character "
                                        + "normalization (+35)."
                        )
                );
            }

            // Catch a one-character insertion, deletion or substitution.
            if (brand.length() >= 4
                    && levenshteinDistance(domainLabel, brand) == 1) {
                return new Analysis(
                        30,
                        List.of(
                                "The registrable domain '" + registrableDomain
                                        + "' differs from the known brand name '"
                                        + brand + "' by one character (+30)."
                        )
                );
            }

            // Catch domains such as paypal-login.example-style domains
            // only when the extra term is in the registrable domain label.
            boolean brandWithSeparator =
                    domainLabel.startsWith(brand + "-")
                            || domainLabel.endsWith("-" + brand);

            if (brandWithSeparator) {
                return new Analysis(
                        25,
                        List.of(
                                "The registrable domain '" + registrableDomain
                                        + "' combines the brand name '" + brand
                                        + "' with an additional hyphenated term (+25)."
                        )
                );
            }
        }

        return new Analysis(0, List.of());
    }

    private String normalizeLookalikes(String value) {
        return value
                .replace('0', 'o')
                .replace('1', 'l')
                .replace('3', 'e')
                .replace('5', 's')
                .replace('7', 't');
    }

    private int levenshteinDistance(String first, String second) {

        int[][] dp = new int[first.length() + 1][second.length() + 1];

        for (int i = 0; i <= first.length(); i++) {
            dp[i][0] = i;
        }

        for (int j = 0; j <= second.length(); j++) {
            dp[0][j] = j;
        }

        for (int i = 1; i <= first.length(); i++) {
            for (int j = 1; j <= second.length(); j++) {

                int cost = first.charAt(i - 1) == second.charAt(j - 1)
                        ? 0 : 1;

                dp[i][j] = Math.min(
                        Math.min(
                                dp[i - 1][j] + 1,
                                dp[i][j - 1] + 1
                        ),
                        dp[i - 1][j - 1] + cost
                );
            }
        }

        return dp[first.length()][second.length()];
    }

    public record Analysis(
            int score,
            List<String> reasons
    ) {
    }
}