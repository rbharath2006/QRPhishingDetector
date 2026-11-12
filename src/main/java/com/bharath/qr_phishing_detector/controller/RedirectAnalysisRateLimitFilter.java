package com.bharath.qr_phishing_detector.controller;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
@ConditionalOnProperty(
        prefix = "app.redirect-analysis",
        name = "enabled",
        havingValue = "true"
)
public class RedirectAnalysisRateLimitFilter extends OncePerRequestFilter {

    private static final String REDIRECT_PATH =
            "/api/v1/redirect-analysis";

    private static final int MAX_REQUESTS_PER_MINUTE = 10;

    private static final long WINDOW_NANOS =
            TimeUnit.MINUTES.toNanos(1);

    private static final int MAX_TRACKED_CLIENTS = 10_000;

    private final ConcurrentMap<String, ClientWindow> clientWindows =
            new ConcurrentHashMap<>();

    private final AtomicLong requestCounter = new AtomicLong();

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !("POST".equalsIgnoreCase(request.getMethod())
                && REDIRECT_PATH.equals(request.getServletPath()));
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        // Use the connection's peer address.
        // Do not trust client-supplied X-Forwarded-For headers here.
        String clientAddress = request.getRemoteAddr();

        if (clientAddress == null || clientAddress.isBlank()) {
            clientAddress = "unknown";
        }

        if (!allowRequest(clientAddress)) {
            response.setStatus(429);
            response.setHeader("Retry-After", "60");
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");

            response.getWriter().write(
                    "{\"error\":\"Redirect-analysis rate limit reached. "
                            + "Please try again later.\"}"
            );

            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean allowRequest(String clientAddress) {
        long now = System.nanoTime();
        long count = requestCounter.incrementAndGet();

        // Periodically remove inactive clients to limit memory growth.
        if (count % 128 == 0
                || clientWindows.size() >= MAX_TRACKED_CLIENTS) {

            clientWindows.entrySet().removeIf(
                    entry -> entry.getValue().isExpired(now)
            );
        }

        ClientWindow existing = clientWindows.get(clientAddress);

        // Fail closed for new client addresses if the tracking map is full.
        if (existing == null
                && clientWindows.size() >= MAX_TRACKED_CLIENTS) {
            return false;
        }

        ClientWindow window = clientWindows.computeIfAbsent(
                clientAddress,
                ignored -> new ClientWindow(now)
        );

        return window.tryAcquire(now);
    }

    private static final class ClientWindow {

        private long windowStartedAt;
        private int requestCount;

        private ClientWindow(long now) {
            this.windowStartedAt = now;
            this.requestCount = 0;
        }

        private synchronized boolean tryAcquire(long now) {
            if (now - windowStartedAt >= WINDOW_NANOS) {
                windowStartedAt = now;
                requestCount = 0;
            }

            if (requestCount >= MAX_REQUESTS_PER_MINUTE) {
                return false;
            }

            requestCount++;
            return true;
        }

        private synchronized boolean isExpired(long now) {
            return now - windowStartedAt >= WINDOW_NANOS;
        }
    }
}