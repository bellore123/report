package com.cybershield.controller;

import com.cybershield.service.PhishingDetectionService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * PhishingController — NEW MODULE.
 *
 * Endpoints:
 *   POST /api/phishing/analyze        → { "url": "..." }
 *   POST /api/phishing/analyze-batch  → { "urls": ["...", "..."] }
 *
 * Available to any authenticated user (ADMIN, SERVER_ADMIN, VIEWER) — this
 * is a personal-safety screening tool, not an admin-only asset operation.
 */
@RestController
@RequestMapping("/api/phishing")
@RequiredArgsConstructor
public class PhishingController {

    private final PhishingDetectionService phishingDetectionService;

    @PostMapping("/analyze")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<?> analyze(@RequestBody Map<String, String> body) {
        String url = body.get("url");
        if (url == null || url.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Please provide a 'url' field."));
        }
        return ResponseEntity.ok(phishingDetectionService.analyze(url));
    }

    @PostMapping("/analyze-batch")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<?> analyzeBatch(@RequestBody Map<String, List<String>> body) {
        List<String> urls = body.get("urls");
        if (urls == null || urls.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Please provide at least one URL."));
        }
        return ResponseEntity.ok(Map.of("results", phishingDetectionService.analyzeBatch(urls)));
    }
}
