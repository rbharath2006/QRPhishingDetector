package com.bharath.qr_phishing_detector.validation;

import com.google.common.net.InternetDomainName;
import org.springframework.stereotype.Service;

import java.util.Locale;
import java.util.Optional;

@Service
public class RegistrableDomainService {

    public Optional<String> findRegistrableDomain(String hostname) {

        if (hostname == null || hostname.isBlank()) {
            return Optional.empty();
        }

        String candidate = hostname.trim().toLowerCase(Locale.ROOT);

        // Remove a trailing DNS root dot if one is present.
        if (candidate.endsWith(".")) {
            candidate = candidate.substring(0, candidate.length() - 1);
        }

        if (candidate.isBlank()) {
            return Optional.empty();
        }

        // IP addresses are not registrable DNS domains.
        if (candidate.contains(":") || isIpv4Literal(candidate)) {
            return Optional.empty();
        }

        try {
            InternetDomainName domain = InternetDomainName.from(candidate);

            // Reject public suffixes themselves and names for which
            // the Public Suffix List cannot identify a registrable domain.
            if (!domain.hasPublicSuffix()
                    || !domain.isUnderPublicSuffix()) {
                return Optional.empty();
            }

            return Optional.of(domain.topPrivateDomain().toString());

        } catch (IllegalArgumentException ex) {
            // Invalid or unsupported hostname syntax.
            return Optional.empty();
        }
    }

    private boolean isIpv4Literal(String hostname) {
        String[] parts = hostname.split("\\.", -1);

        if (parts.length != 4) {
            return false;
        }

        for (String part : parts) {
            if (part.isEmpty()) {
                return false;
            }

            try {
                int value = Integer.parseInt(part);

                if (value < 0 || value > 255) {
                    return false;
                }
            } catch (NumberFormatException ex) {
                return false;
            }
        }

        return true;
    }
}