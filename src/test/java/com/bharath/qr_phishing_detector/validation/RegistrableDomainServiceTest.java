package com.bharath.qr_phishing_detector.validation;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class RegistrableDomainServiceTest {

    private final RegistrableDomainService service =
            new RegistrableDomainService();

    @Test
    void extractsRegistrableDomainFromComHostname() {
        assertEquals(
                Optional.of("example.com"),
                service.findRegistrableDomain(
                        "login.accounts.example.com"
                )
        );
    }

    @Test
    void handlesMultiLevelPublicSuffix() {
        assertEquals(
                Optional.of("example.co.uk"),
                service.findRegistrableDomain(
                        "login.example.co.uk"
                )
        );
    }

    @Test
    void handlesDomainThatIsAlreadyRegistrable() {
        assertEquals(
                Optional.of("example.com"),
                service.findRegistrableDomain("example.com")
        );
    }

    @Test
    void ignoresIpv4Addresses() {
        assertTrue(
                service.findRegistrableDomain("192.0.2.10").isEmpty()
        );
    }

    @Test
    void ignoresIpv6Addresses() {
        assertTrue(
                service.findRegistrableDomain("2001:db8::1").isEmpty()
        );
    }

    @Test
    void ignoresLocalhost() {
        assertTrue(
                service.findRegistrableDomain("localhost").isEmpty()
        );
    }

    @Test
    void handlesEmptyInput() {
        assertTrue(
                service.findRegistrableDomain(" ").isEmpty()
        );
    }
}