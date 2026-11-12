package com.bharath.qr_phishing_detector.controller;

import com.bharath.qr_phishing_detector.dto.FeedStatusResponse;
import com.bharath.qr_phishing_detector.service.FeedStatusService;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/feeds")
public class FeedStatusController {

    private final FeedStatusService feedStatusService;

    public FeedStatusController(FeedStatusService feedStatusService) {
        this.feedStatusService = feedStatusService;
    }

    @GetMapping("/status")
    public List<FeedStatusResponse> getFeedStatus() {
        return feedStatusService.getAllStatuses();
    }
}