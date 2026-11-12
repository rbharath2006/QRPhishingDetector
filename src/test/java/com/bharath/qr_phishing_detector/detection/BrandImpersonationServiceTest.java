package com.bharath.qr_phishing_detector.detection;

import com.bharath.qr_phishing_detector.validation.RegistrableDomainService;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class BrandImpersonationServiceTest {

    private final BrandImpersonationService service =
            new BrandImpersonationService(
                    new RegistrableDomainService()
            );

    @Test
    void flagsDigitLookalikeInBrandDomain() {
        var result = service.analyze("paypa1.com");

        assertEquals(35, result.score());
        assertFalse(result.reasons().isEmpty());
    }

    @Test
    void flagsSingleCharacterTypo() {
        var result = service.analyze("gogle.com");

        assertEquals(30, result.score());
        assertFalse(result.reasons().isEmpty());
    }

    @Test
    void doesNotFlagExactListedBrandDomain() {
        var result = service.analyze("paypal.com");

        assertEquals(0, result.score());
        assertTrue(result.reasons().isEmpty());
    }

    @Test
    void doesNotFlagOrdinaryExampleDomain() {
        var result = service.analyze("example.com");

        assertEquals(0, result.score());
        assertTrue(result.reasons().isEmpty());
    }

    @Test
    void checksRegistrableDomainRatherThanSubdomainText() {
        var result = service.analyze("login.paypal.com");

        assertEquals(0, result.score());
    }

    @Test
    void returnsNoWarningForLocalHostname() {
        var result = service.analyze("localhost");

        assertEquals(0, result.score());
        assertTrue(result.reasons().isEmpty());
    }
}