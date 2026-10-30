package com.cybershield.controller;

import com.cybershield.model.CollegeEvent;
import com.cybershield.service.CollegeEventService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;

/**
 * CollegeEventController — receives attack beacons from college sites
 * (College A at localhost:8082, College E at localhost:8083) and serves
 * live event data to the SOC dashboard.
 *
 * Endpoints (ALL PUBLIC — no JWT required for POST, college sites are public):
 *   POST /api/college-events           → receive beacon from a college page
 *   GET  /api/college-events/recent    → last 50 events (dashboard polling)
 *   GET  /api/college-events/live      → per-college live threat summary cards
 *
 * Security note: POST is intentionally public so college-site JS can beacon
 * without auth. GET endpoints are also public so the dashboard panel works
 * even when viewing as a guest (same policy as the existing dashboard.html page).
 */
@RestController
@RequestMapping("/api/college-events")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "*")   // college sites on different ports need CORS
public class CollegeEventController {

    private final CollegeEventService collegeEventService;

    /**
     * POST /api/college-events
     *
     * Receives a JSON beacon from a college site page.
     * Detects attack patterns, computes risk, optionally creates an Incident,
     * and stores the event in the rolling buffer.
     *
     * Example payload from college-a/login.html:
     * {
     *   "institutionCode": "COL-A-SOUTH",
     *   "collegeName":     "College A - South Campus",
     *   "page":            "login",
     *   "eventType":       "LOGIN_ATTEMPT",
     *   "inputPayload":    "admin' OR 1=1--",
     *   "attackerIp":      "auto-filled below from request"
     * }
     */
    @PostMapping
    public ResponseEntity<CollegeEvent> receiveEvent(@RequestBody CollegeEvent event,
                                                     HttpServletRequest request) {
        // Auto-fill attackerIp from the real HTTP request if not set by the JS
        if (event.getAttackerIp() == null || event.getAttackerIp().isBlank()
                || "auto-detected".equals(event.getAttackerIp())) {
            String xff = request.getHeader("X-Forwarded-For");
            event.setAttackerIp(
                    (xff != null && !xff.isBlank()) ? xff.split(",")[0].trim()
                                                    : request.getRemoteAddr()
            );
        }

        CollegeEvent processed = collegeEventService.processEvent(event);
        return ResponseEntity.ok(processed);
    }

    /**
     * GET /api/college-events/recent?limit=50
     *
     * Returns the last N events (newest first) for the live event feed table
     * in the SOC dashboard.
     */
    @GetMapping("/recent")
    public ResponseEntity<List<CollegeEvent>> getRecentEvents(
            @RequestParam(defaultValue = "50") int limit) {
        return ResponseEntity.ok(collegeEventService.getRecentEvents(limit));
    }

    /**
     * GET /api/college-events/live
     *
     * Returns one summary card per monitored college — used to render
     * the "College Live Threat Monitor" panel in dashboard.html.
     *
     * Each card: { institutionCode, collegeName, city, status, riskScore,
     *              severity, lastAttack, lastSeen, serverIp, serverName,
     *              eventType, eventCount, incidentId }
     */
    @GetMapping("/live")
    public ResponseEntity<List<Map<String, Object>>> getLiveSummary() {
        return ResponseEntity.ok(collegeEventService.getLiveSummary());
    }
}
