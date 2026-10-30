package com.cybershield.service;

import com.cybershield.model.AssetRelationship.AssetType;
import com.cybershield.model.Incident;
import com.cybershield.model.Incident.IncidentStatus;
import com.cybershield.model.Incident.Severity;
import com.cybershield.repository.IncidentRepository;
import com.cybershield.repository.UserRepository;
import com.cybershield.service.RiskEngineService.RiskResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

/**
 * IncidentService — creates and manages security incidents.
 *
 * FIX 1B: Duplicate check now uses username for user incidents (not null).
 * FIX 1C: Attack path uses dynamic user ID looked up from DB (not hardcoded 3L).
 *
 * Called by:
 *   1. AuthService (after every LOGIN_FAIL via triggerUserRiskCheck)
 *   2. RiskController (on-demand evaluate endpoint)
 *
 * Auto-incident thresholds:
 *   score ≥ 50  → LOW
 *   score ≥ 70  → MEDIUM
 *   score ≥ 85  → HIGH
 *   score ≥ 95  → CRITICAL
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class IncidentService {

    private final IncidentRepository incidentRepository;
    private final RiskEngineService  riskEngineService;
    private final AttackPathService  attackPathService;
    private final UserRepository     userRepository;     // FIX 1C: for dynamic user ID lookup
    private final AlertService       alertService;        // ENHANCEMENT: email alerts on HIGH/CRITICAL

    // ─────────────────────────────────────────────────────────────────────
    // TRIGGER — called by AuthService on every LOGIN_FAIL
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Evaluate risk for a user and auto-create an incident if score ≥ 50.
     *
     * @param username  The user being attacked
     * @param sourceIp  IP address of the attacker
     */
    public void triggerUserRiskCheck(String username, String sourceIp) {
        RiskResult result = riskEngineService.calculateUserRisk(username);
        log.info("Risk check for user '{}': score={}", username, result.score);

        if (result.score >= 30) {
            createUserIncident(result, username, sourceIp);
        }
    }

    /**
     * Evaluate risk for a server and auto-create an incident if score ≥ 50.
     * Called from RiskController when explicitly requested.
     */
    public Incident evaluateAndCreateServerIncident(Long serverId) {
        RiskResult result = riskEngineService.calculateServerRisk(serverId);

        if (result.score >= 50) {
            return createServerIncident(result, serverId);
        }
        return null;
    }

    // ─────────────────────────────────────────────────────────────────────
    // INCIDENT CREATION — private helpers
    // ─────────────────────────────────────────────────────────────────────

    private void createUserIncident(RiskResult result, String username, String sourceIp) {
        // FIX 1B: Correct duplicate check using username (was passing null before)
        boolean alreadyOpen = incidentRepository
                .existsByAffectedUsernameAndStatusIn(
                        username,
                        List.of(IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED));

        if (alreadyOpen) {
            log.info("Incident already open for user '{}' — skipping duplicate", username);
            return;
        }

        Severity severity = riskEngineService.scoreToSeverity(result.score);

        // FIX 1C: Look up real user ID dynamically from DB (was hardcoded 3L)
        String attackPathSummary = "";
        try {
            var userOpt = userRepository.findByUsername(username);
            if (userOpt.isPresent()) {
                Long realUserId = userOpt.get().getId();
                // Try to find a path from this user to any server (use first server ID=1)
                var pathResult = attackPathService.findShortestPath(
                        realUserId, AssetType.USER, 1L, AssetType.SERVER);
                if (pathResult.found) {
                    attackPathSummary = pathResult.summary;
                }
            }
        } catch (Exception e) {
            log.warn("Could not compute attack path for user '{}': {}", username, e.getMessage());
        }

        String title = String.format("[%s] Brute Force Detected — account '%s'",
                severity.name(), username);

        String description = String.format(
                "Risk score: %d/100. " +
                "Breakdown: %s. " +
                "Source IP: %s. " +
                "Repeated login failures detected. " +
                "Account auto-locked after 5 consecutive failures. " +
                "%s",
                result.score, result.breakdown, sourceIp,
                attackPathSummary.isEmpty() ? "" :
                    "Attack path if compromised: " + attackPathSummary);

        Incident incident = Incident.builder()
                .title(title)
                .description(description)
                .severity(severity)
                .status(IncidentStatus.OPEN)
                .relatedAssetType(AssetType.USER)
                .riskScore(result.score)
                .affectedUsername(username)
                .sourceIp(sourceIp)
                .attackPath(attackPathSummary)
                .build();

        Incident saved = incidentRepository.save(incident);
        log.warn("INCIDENT CREATED [{}] id={} — '{}'", severity, saved.getId(), title);
        alertService.sendIncidentAlert(saved); // ENHANCEMENT: email alert for HIGH/CRITICAL
    }

    private Incident createServerIncident(RiskResult result, Long serverId) {
        // Prevent duplicate open incident for same server
        if (incidentRepository.existsByRelatedAssetIdAndStatusIn(
                serverId, List.of(IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED))) {
            log.info("Incident already open for server {} — skipping duplicate", serverId);
            return null;
        }

        Severity severity = riskEngineService.scoreToSeverity(result.score);

        // FIX 1C: Dynamically compute attack path — not hardcoded user ID
        String attackPathSummary = "";
        try {
            // Try path from all 3 seeded users (admin=1, serveradmin=2, viewer=3)
            // Use viewer (lowest privilege) as most likely attacker entry point
            // But resolve actual ID from DB
            var viewerOpt = userRepository.findByUsername("viewer");
            if (viewerOpt.isPresent()) {
                Long viewerUserId = viewerOpt.get().getId();
                var pathResult = attackPathService.findShortestPath(
                        viewerUserId, AssetType.USER, serverId, AssetType.SERVER);
                if (pathResult.found) {
                    attackPathSummary = pathResult.summary;
                }
            }
        } catch (Exception e) {
            log.warn("Could not compute attack path for server {}: {}", serverId, e.getMessage());
        }

        String title = String.format("[%s] High Risk Server — Server ID %d",
                severity.name(), serverId);

        String description = String.format(
                "Risk score: %d/100. " +
                "Breakdown: %s. " +
                "%s" +
                "Immediate review recommended.",
                result.score,
                result.breakdown,
                attackPathSummary.isEmpty() ? "" :
                    "Attack path: [" + attackPathSummary + "]. ");

        Incident incident = Incident.builder()
                .title(title)
                .description(description)
                .severity(severity)
                .status(IncidentStatus.OPEN)
                .relatedAssetId(serverId)
                .relatedAssetType(AssetType.SERVER)
                .riskScore(result.score)
                .attackPath(attackPathSummary)
                .build();

        Incident saved = incidentRepository.save(incident);
        log.warn("INCIDENT CREATED [{}] id={} — '{}'", severity, saved.getId(), title);
        alertService.sendIncidentAlert(saved); // ENHANCEMENT: email alert for HIGH/CRITICAL
        return saved;
    }

    // ─────────────────────────────────────────────────────────────────────
    // COLLEGE ATTACK — create incident from college site beacon
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Creates an incident when a college site reports an attack event.
     * Called by CollegeEventService when risk score >= 60.
     *
     * @param serverId      ID of the server being targeted
     * @param collegeName   Human-readable college name (e.g. "College A - South Campus")
     * @param attackPattern What was detected (e.g. "SQL Injection on login page")
     * @param page          Which page the attack happened on
     * @param riskScore     Pre-computed risk score from CollegeEventService
     * @param attackerIp    Source IP of the attacker
     */
    public Incident createCollegeAttackIncident(Long serverId, String collegeName,
                                                String attackPattern, String page,
                                                int riskScore, String attackerIp) {
        Severity severity = riskEngineService.scoreToSeverity(riskScore);

        String title = String.format("[%s] %s — %s (%s)",
                severity.name(), attackPattern, collegeName, page);

        String description = String.format(
                "College site attack beacon received. " +
                "Institution: %s. " +
                "Page: %s. " +
                "Attack: %s. " +
                "Risk Score: %d/100. " +
                "Attacker IP: %s. " +
                "Server ID: %d. " +
                "Immediate investigation recommended.",
                collegeName, page, attackPattern, riskScore, attackerIp, serverId);

        Incident incident = Incident.builder()
                .title(title)
                .description(description)
                .severity(severity)
                .status(IncidentStatus.OPEN)
                .relatedAssetId(serverId)
                .relatedAssetType(AssetType.SERVER)
                .riskScore(riskScore)
                .sourceIp(attackerIp)
                .attackPath("External → " + collegeName + " → Server ID " + serverId)
                .build();

        Incident saved = incidentRepository.save(incident);
        log.warn("COLLEGE INCIDENT [{}] id={} — '{}'", severity, saved.getId(), title);
        alertService.sendIncidentAlert(saved);
        return saved;
    }

    // ─────────────────────────────────────────────────────────────────────
    // CRUD — Incident management
    // ─────────────────────────────────────────────────────────────────────

    public List<Incident> getAllIncidents() {
        return incidentRepository.findAllByOrderByCreatedAtDesc();
    }

    public List<Incident> getOpenIncidents() {
        return incidentRepository.findByStatusOrderByCreatedAtDesc(IncidentStatus.OPEN);
    }

    public long countOpenIncidents() {
        return incidentRepository.countByStatus(IncidentStatus.OPEN);
    }

    public Incident resolveIncident(Long id, String resolvedBy) {
        return resolveIncident(id, resolvedBy, null);
    }

    public Incident resolveIncident(Long id, String resolvedBy, String finalNotes) {
        Incident incident = incidentRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Incident not found: " + id));
        incident.setStatus(IncidentStatus.RESOLVED);
        incident.setResolvedAt(LocalDateTime.now());
        incident.setResolvedBy(resolvedBy);
        if (finalNotes != null && !finalNotes.isBlank()) {
            String existing = incident.getRemediationNotes() != null ? incident.getRemediationNotes() + " | " : "";
            incident.setRemediationNotes(existing + "Resolved: " + finalNotes);
        }
        Incident saved = incidentRepository.save(incident);
        log.info("Incident {} resolved by {}", id, resolvedBy);
        return saved;
    }

    public Incident containIncident(Long id, String containedBy, String remediationNotes) {
        Incident incident = incidentRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Incident not found: " + id));
        incident.setStatus(IncidentStatus.CONTAINED);
        incident.setContainedAt(LocalDateTime.now());
        incident.setContainedBy(containedBy);
        if (remediationNotes != null && !remediationNotes.isBlank()) {
            String existing = incident.getRemediationNotes() != null ? incident.getRemediationNotes() + " | " : "";
            incident.setRemediationNotes(existing + "Contained: " + remediationNotes);
        }
        Incident saved = incidentRepository.save(incident);
        log.info("Incident {} marked CONTAINED by {}: {}", id, containedBy, remediationNotes);
        return saved;
    }

    public Incident markInvestigating(Long id) {
        return markInvestigating(id, null);
    }

    public Incident markInvestigating(Long id, String assignedTo) {
        Incident incident = incidentRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Incident not found: " + id));
        incident.setStatus(IncidentStatus.INVESTIGATING);
        if (assignedTo != null && !assignedTo.isBlank()) {
            incident.setAssignedTo(assignedTo);
        }
        Incident saved = incidentRepository.save(incident);
        log.info("Incident {} marked INVESTIGATING (assigned to '{}')", id, assignedTo);
        return saved;
    }

    public Incident updateRemediationNotes(Long id, String notes) {
        Incident incident = incidentRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Incident not found: " + id));
        incident.setRemediationNotes(notes);
        return incidentRepository.save(incident);
    }
}
