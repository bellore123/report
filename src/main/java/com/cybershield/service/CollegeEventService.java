package com.cybershield.service;

import com.cybershield.model.CollegeEvent;
import com.cybershield.model.Incident;
import com.cybershield.model.Server;
import com.cybershield.repository.ServerRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.stream.Collectors;

/**
 * CollegeEventService — processes attack/access beacons received from
 * college-site pages (College A / College E).
 *
 * Responsibilities:
 *   1. Detect attack patterns from the incoming event payload
 *   2. Compute a risk score for the event
 *   3. Store the event in a rolling in-memory ring buffer (last 200)
 *   4. Auto-create an Incident via IncidentService if risk >= 60
 *   5. Serve the live event list to the dashboard polling endpoint
 *
 * Server → College mapping:
 *   NEDI-STUDENT-WEB-01 (id=1, 10.0.1.10) → College A — student/login pages
 *   NEDI-EXAM-APP-01    (id=2, 10.0.1.11) → College A+E — exam pages
 *   NEDI-EXAM-DB-01     (id=3, 10.0.1.12) → College A+E — exam DB (backend)
 *   NEDI-FACULTY-WEB-01 (id=4, 10.0.1.13) → College E   — faculty pages
 *   NEDI-ERP-APP-01     (id=5, 10.0.1.14) → College E   — erp/admin pages
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CollegeEventService {

    private final IncidentService    incidentService;
    private final ServerRepository   serverRepository;

    /** Rolling ring buffer — last 200 events, thread-safe */
    private final Deque<CollegeEvent> eventBuffer = new ConcurrentLinkedDeque<>();
    private static final int MAX_EVENTS = 200;

    /** Brute-force tracking: IP → list of timestamps of login attempts */
    private final Map<String, Deque<LocalDateTime>> bruteForceTracker = new HashMap<>();

    // ─── SQL Injection patterns ───────────────────────────────────────
    private static final List<String> SQLI_PATTERNS = List.of(
            "'", "\"", "--", ";--", "/*", "*/", "xp_", "OR 1=1", "OR '1'='1'",
            "UNION SELECT", "DROP TABLE", "INSERT INTO", "DELETE FROM",
            "1=1", "admin'--", "' OR '", "1' OR '1'='1"
    );

    // ─── XSS patterns ────────────────────────────────────────────────
    private static final List<String> XSS_PATTERNS = List.of(
            "<script", "javascript:", "onerror=", "onload=", "alert(", "document.cookie"
    );

    // ─────────────────────────────────────────────────────────────────
    // MAIN: process a beacon from a college site page
    // ─────────────────────────────────────────────────────────────────
    public CollegeEvent processEvent(CollegeEvent incoming) {

        // 1. Resolve server mapping based on institution + page
        resolveServer(incoming);

        // 2. Detect attack pattern
        detectPattern(incoming);

        // 3. Compute risk score
        int score = computeRisk(incoming);
        incoming.setRiskScore(score);
        incoming.setSeverity(getSeverityLabel(score));

        // 4. Assign UUID + timestamp
        incoming.setId(UUID.randomUUID().toString().substring(0, 8).toUpperCase());
        incoming.setTimestamp(LocalDateTime.now());

        // 5. Auto-create incident if HIGH or CRITICAL
        if (score >= 60 && incoming.getServerId() != null) {
            try {
                Incident incident = incidentService.createCollegeAttackIncident(
                        incoming.getServerId(),
                        incoming.getCollegeName(),
                        incoming.getAttackPattern(),
                        incoming.getPage(),
                        score,
                        incoming.getAttackerIp()
                );
                if (incident != null) {
                    incoming.setIncidentCreated(true);
                    incoming.setIncidentId(incident.getId());
                    log.warn("INCIDENT CREATED: {} | {} | Score={} | Server={}",
                            incoming.getCollegeName(), incoming.getAttackPattern(),
                            score, incoming.getServerName());
                }
            } catch (Exception e) {
                log.warn("Could not create incident for college event: {}", e.getMessage());
            }
        }

        // 6. Store in rolling buffer
        store(incoming);

        log.info("CollegeEvent [{}] {} | {} | {} | Score={}",
                incoming.getId(), incoming.getCollegeName(),
                incoming.getPage(), incoming.getAttackPattern(), score);

        return incoming;
    }

    // ─────────────────────────────────────────────────────────────────
    // SERVER MAPPING — college + page → server
    // ─────────────────────────────────────────────────────────────────
    private void resolveServer(CollegeEvent e) {
        String code = e.getInstitutionCode();
        String page = e.getPage() != null ? e.getPage().toLowerCase() : "";

        String serverName;
        Long   serverId;
        String serverIp;

        if ("COL-A-SOUTH".equals(code)) {
            e.setCollegeCity("Chennai, Tamil Nadu");
            if (page.contains("exam")) {
                serverId = 2L; serverName = "NEDI-EXAM-APP-01"; serverIp = "10.0.1.11";
            } else if (page.contains("faculty")) {
                serverId = 4L; serverName = "NEDI-FACULTY-WEB-01"; serverIp = "10.0.1.13";
            } else if (page.contains("admin") || page.contains("erp")) {
                serverId = 5L; serverName = "NEDI-ERP-APP-01"; serverIp = "10.0.1.14";
            } else {
                // login, index, student
                serverId = 1L; serverName = "NEDI-STUDENT-WEB-01"; serverIp = "10.0.1.10";
            }
        } else { // COL-E-CENTRAL
            e.setCollegeCity("Bhopal, Madhya Pradesh");
            if (page.contains("exam")) {
                serverId = 2L; serverName = "NEDI-EXAM-APP-01"; serverIp = "10.0.1.11";
            } else if (page.contains("faculty")) {
                serverId = 4L; serverName = "NEDI-FACULTY-WEB-01"; serverIp = "10.0.1.13";
            } else if (page.contains("erp") || page.contains("admin")) {
                serverId = 5L; serverName = "NEDI-ERP-APP-01"; serverIp = "10.0.1.14";
            } else {
                serverId = 1L; serverName = "NEDI-STUDENT-WEB-01"; serverIp = "10.0.1.10";
            }
        }

        e.setServerId(serverId);
        e.setServerName(serverName);
        e.setServerIp(serverIp);
    }

    // ─────────────────────────────────────────────────────────────────
    // PATTERN DETECTION
    // ─────────────────────────────────────────────────────────────────
    private void detectPattern(CollegeEvent e) {
        String payload = e.getInputPayload() != null ? e.getInputPayload().toUpperCase() : "";
        String eventType = e.getEventType() != null ? e.getEventType().toUpperCase() : "";

        // 1. Check explicit eventType set by the site JS
        if (eventType.equals("SQL_INJECTION") || isSqli(payload)) {
            e.setEventType("SQL_INJECTION");
            e.setAttackPattern("SQL Injection Detected in " + e.getPage() + " form");
            return;
        }
        if (eventType.equals("XSS") || isXss(payload)) {
            e.setEventType("XSS");
            e.setAttackPattern("Cross-Site Scripting (XSS) payload in " + e.getPage() + " field");
            return;
        }
        if (eventType.equals("BRUTE_FORCE") || isBruteForce(e)) {
            e.setEventType("BRUTE_FORCE");
            e.setAttackPattern("Brute Force login attempt on " + e.getPage() + " from " + e.getAttackerIp());
            return;
        }
        if (eventType.equals("RECON") || e.getPage() != null && e.getPage().equalsIgnoreCase("admin")) {
            e.setEventType("RECON");
            e.setAttackPattern("Reconnaissance — Admin panel access attempt");
            return;
        }

        // Default: normal access
        if (e.getEventType() == null || e.getEventType().isBlank()) {
            e.setEventType("PAGE_ACCESS");
        }
        if (e.getAttackPattern() == null || e.getAttackPattern().isBlank()) {
            e.setAttackPattern("Normal page access — " + e.getPage());
        }
    }

    private boolean isSqli(String payload) {
        if (payload == null || payload.isBlank()) return false;
        String up = payload.toUpperCase();
        return SQLI_PATTERNS.stream().anyMatch(p -> up.contains(p.toUpperCase()));
    }

    private boolean isXss(String payload) {
        if (payload == null || payload.isBlank()) return false;
        String up = payload.toUpperCase();
        return XSS_PATTERNS.stream().anyMatch(p -> up.contains(p.toUpperCase()));
    }

    private boolean isBruteForce(CollegeEvent e) {
        if (!"LOGIN_ATTEMPT".equalsIgnoreCase(e.getEventType())) return false;
        String ip = e.getAttackerIp() != null ? e.getAttackerIp() : "unknown";
        bruteForceTracker.putIfAbsent(ip, new ArrayDeque<>());
        Deque<LocalDateTime> times = bruteForceTracker.get(ip);
        times.addLast(LocalDateTime.now());
        // Keep only last 60 seconds of timestamps
        LocalDateTime cutoff = LocalDateTime.now().minusSeconds(60);
        while (!times.isEmpty() && times.peekFirst().isBefore(cutoff)) {
            times.pollFirst();
        }
        return times.size() >= 4; // 4+ logins in 60 seconds = brute force
    }

    // ─────────────────────────────────────────────────────────────────
    // RISK SCORING
    // ─────────────────────────────────────────────────────────────────
    private int computeRisk(CollegeEvent e) {
        int score = 10; // base

        switch (e.getEventType() != null ? e.getEventType().toUpperCase() : "") {
            case "SQL_INJECTION" -> score += 65;
            case "XSS"           -> score += 45;
            case "BRUTE_FORCE"   -> score += 50;
            case "RECON"         -> score += 30;
            case "LOGIN_ATTEMPT" -> score += 10;
            case "EXAM_ACCESS"   -> score += 5;
            case "FACULTY_ACCESS"-> score += 5;
            default              -> score += 0;
        }

        // Bonus: College E is already HIGH_RISK — amplify
        if ("COL-E-CENTRAL".equals(e.getInstitutionCode())) {
            score = Math.min(100, score + 10);
        }

        // Bonus: hitting the unpatched Exam server (10.0.1.11) — extra risk
        if ("NEDI-EXAM-APP-01".equals(e.getServerName())) {
            score = Math.min(100, score + 15);
        }

        return Math.min(100, score);
    }

    private String getSeverityLabel(int score) {
        if (score >= 80) return "CRITICAL";
        if (score >= 60) return "HIGH";
        if (score >= 40) return "MEDIUM";
        return "LOW";
    }

    // ─────────────────────────────────────────────────────────────────
    // STORAGE — rolling ring buffer
    // ─────────────────────────────────────────────────────────────────
    private void store(CollegeEvent e) {
        eventBuffer.addFirst(e); // newest first
        while (eventBuffer.size() > MAX_EVENTS) {
            eventBuffer.pollLast();
        }
    }

    /** Last N events (newest first) — used by dashboard polling */
    public List<CollegeEvent> getRecentEvents(int limit) {
        return eventBuffer.stream().limit(limit).collect(Collectors.toList());
    }

    /** Per-institution live summary for the dashboard cards */
    public List<Map<String, Object>> getLiveSummary() {
        Map<String, Map<String, Object>> byCollege = new LinkedHashMap<>();

        // Pre-populate all known colleges so the dashboard always shows them
        initCollegeCard(byCollege, "COL-A-SOUTH",  "College A - South Campus",   "Chennai, Tamil Nadu",     "ACTIVE");
        initCollegeCard(byCollege, "COL-E-CENTRAL", "College E - Central Region", "Bhopal, Madhya Pradesh",  "HIGH_RISK");

        // Merge actual events
        for (CollegeEvent evt : eventBuffer) {
            String code = evt.getInstitutionCode();
            if (!byCollege.containsKey(code)) continue;
            Map<String, Object> card = byCollege.get(code);

            int existing = (int) card.getOrDefault("riskScore", 0);
            if (evt.getRiskScore() > existing) {
                card.put("riskScore",     evt.getRiskScore());
                card.put("severity",      evt.getSeverity());
                card.put("lastAttack",    evt.getAttackPattern());
                card.put("lastSeen",      evt.getTimestamp().toString());
                card.put("serverIp",      evt.getServerIp());
                card.put("serverName",    evt.getServerName());
                card.put("eventType",     evt.getEventType());
                card.put("incidentId",    evt.getIncidentId());
            }
            card.put("eventCount", (int) card.getOrDefault("eventCount", 0) + 1);
        }

        return new ArrayList<>(byCollege.values());
    }

    private void initCollegeCard(Map<String, Map<String, Object>> map,
                                 String code, String name, String city, String status) {
        Map<String, Object> card = new LinkedHashMap<>();
        card.put("institutionCode", code);
        card.put("collegeName",     name);
        card.put("city",            city);
        card.put("status",          status);
        card.put("riskScore",       0);
        card.put("severity",        "LOW");
        card.put("lastAttack",      "—");
        card.put("lastSeen",        "—");
        card.put("serverIp",        "—");
        card.put("serverName",      "—");
        card.put("eventType",       "—");
        card.put("eventCount",      0);
        card.put("incidentId",      null);
        map.put(code, card);
    }
}
