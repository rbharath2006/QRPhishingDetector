package com.bharath.qr_phishing_detector.controller;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RedirectAnalysisRateLimitFilterTest {

    private static final String REDIRECT_PATH =
            "/api/v1/redirect-analysis";

    @Test
    void allowsTenRequestsAndRejectsTheEleventh() throws Exception {
        RedirectAnalysisRateLimitFilter filter =
                new RedirectAnalysisRateLimitFilter();

        AtomicInteger requestsReachedEndpoint = new AtomicInteger();

        FilterChain chain = (request, response) -> {
            requestsReachedEndpoint.incrementAndGet();
            ((HttpServletResponse) response).setStatus(200);
        };

        // First ten requests from the same client should be allowed.
        for (int i = 0; i < 10; i++) {
            MockHttpServletRequest request = request(
                    "POST", REDIRECT_PATH, "192.0.2.10"
            );

            MockHttpServletResponse response =
                    new MockHttpServletResponse();

            filter.doFilter(request, response, chain);

            assertEquals(200, response.getStatus());
        }

        // The eleventh request should be rate limited.
        MockHttpServletRequest request = request(
                "POST", REDIRECT_PATH, "192.0.2.10"
        );

        MockHttpServletResponse response =
                new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        assertEquals(429, response.getStatus());
        assertEquals("60", response.getHeader("Retry-After"));
        assertEquals(10, requestsReachedEndpoint.get());
    }

    @Test
    void doesNotLimitUnrelatedEndpoints() throws Exception {
        RedirectAnalysisRateLimitFilter filter =
                new RedirectAnalysisRateLimitFilter();

        MockHttpServletRequest request = request(
                "POST",
                "/api/v1/intelligence/lookup",
                "192.0.2.20"
        );

        MockHttpServletResponse response =
                new MockHttpServletResponse();

        AtomicInteger calls = new AtomicInteger();

        FilterChain chain = (req, res) -> {
            calls.incrementAndGet();
            ((HttpServletResponse) res).setStatus(200);
        };

        filter.doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        assertEquals(1, calls.get());
    }

    private MockHttpServletRequest request(
            String method,
            String path,
            String ip
    ) {
        MockHttpServletRequest request =
                new MockHttpServletRequest(method, path);

        request.setServletPath(path);
        request.setRemoteAddr(ip);

        return request;
    }
}