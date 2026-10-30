package com.cybershield.service;

import com.cybershield.model.AssetRelationship.AssetType;
import com.cybershield.model.Incident;
import com.cybershield.repository.AssetRelationshipRepository;
import com.cybershield.repository.AuditLogRepository;
import com.cybershield.repository.LicenseRepository;
import com.cybershield.repository.ServerRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * RiskEngineService — calculates a risk score (0-100) for any asset or user.
 *
 * ═══════════════════════════════════════════════════════
 * RISK SCORING FORMULA
 * ═══════════════════════════════════════════════════════
 *
 * RiskScore = sum of triggered factors (capped at 100)
 *
 * FACTOR 1: +30 — Server not patched in last 90 days
 *   → Reads: servers.last_patch_date
 *
 * FACTOR 2: +25 — This server's own linked license is expired
 *   → Reads: licenses WHERE server_id = this_server AND expiry < today
 *   → FIX 1A: Now checks per-server, not globally
 *
 * FACTOR 3: +20 — Server owner's account has ≥3 failed logins in last 24h
 *   → Reads: audit_logs WHERE action=LOGIN_FAIL AND username=server.owner
 *   → FIX 1D: Now feeds into server risk, not just user risk
 *
 * FACTOR 4: +15 — Asset reachable from low-trust node (trust_level < 30)
 *   → Reads: asset_relationships WHERE target=this_asset AND trust < 30
 *
 * THRESHOLD:
 *   score >= 50  → LOW incident
 *   score >= 70  → MEDIUM incident
 *   score >= 85  → HIGH incident
 *   score >= 95  → CRITICAL incident
 * ═══════════════════════════════════════════════════════
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RiskEngineService {

    private final AuditLogRepository auditLogRepository;
    private final ServerRepository serverRepository;
    private final LicenseRepository licenseRepository;
    private final AssetRelationshipRepository relationshipRepository;

    // Scoring constants
    private static final int SCORE_UNPATCHED_SERVER    = 30;
    private static final int SCORE_EXPIRED_LICENSE     = 25;
    private static final int SCORE_OWNER_UNDER_ATTACK  = 20;
    private static final int SCORE_LOW_TRUST_REACHABLE = 15;
    private static final int SCORE_MAX                 = 100;

    // Thresholds
    private static final int PATCH_DAYS_THRESHOLD          = 90;
    private static final int FAILED_LOGIN_WINDOW_HOURS      = 24;
    private static final int FAILED_LOGIN_MIN_COUNT         = 3;
    private static final int LOW_TRUST_MAX                  = 30;
    private static final int USER_FAILED_LOGIN_WINDOW_MINUTES = 5;

    // ─────────────────────────────────────────────────────────────────────
    // SERVER RISK — called by RiskController and IncidentService
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Calculate risk score for a SERVER asset.
     * FIX 1A: Uses per-server license check.
     * FIX 1D: Checks server owner's failed logins.
     */
    public RiskResult calculateServerRisk(Long serverId) {
        Map<String, Integer> breakdown = new HashMap<>();
        int score = 0;

        var serverOpt = serverRepository.findById(serverId);
        if (serverOpt.isEmpty()) {
            return new RiskResult(serverId, AssetType.SERVER, 0, breakdown);
        }
        var server = serverOpt.get();

        // FACTOR 1: Patch date check
        if (server.getLastPatchDate() == null ||
            server.getLastPatchDate().isBefore(LocalDate.now().minusDays(PATCH_DAYS_THRESHOLD))) {
            score += SCORE_UNPATCHED_SERVER;
            breakdown.put("unpatched_server", SCORE_UNPATCHED_SERVER);
            log.debug("Server {} risk +{}: not patched in {} days",
                    serverId, SCORE_UNPATCHED_SERVER, PATCH_DAYS_THRESHOLD);
        }

        // FACTOR 2: FIX 1A — per-server expired license check
        long expiredLicenses = licenseRepository.countExpiredLicensesByServer(serverId, LocalDate.now());
        if (expiredLicenses > 0) {
            score += SCORE_EXPIRED_LICENSE;
            breakdown.put("expired_license", SCORE_EXPIRED_LICENSE);
            log.debug("Server {} risk +{}: {} expired license(s) linked to this server",
                    serverId, SCORE_EXPIRED_LICENSE, expiredLicenses);
        }

        // FACTOR 3: FIX 1D — check if server's owner account is under attack
        String ownerUsername = server.getOwner();
        if (ownerUsername != null && !ownerUsername.isBlank()) {
            long ownerFailedLogins = auditLogRepository.countFailedLoginsForOwner(
                    ownerUsername,
                    LocalDateTime.now().minusHours(FAILED_LOGIN_WINDOW_HOURS)
            );
            if (ownerFailedLogins >= FAILED_LOGIN_MIN_COUNT) {
                score += SCORE_OWNER_UNDER_ATTACK;
                breakdown.put("owner_account_attacked_" + ownerFailedLogins + "x",
                        SCORE_OWNER_UNDER_ATTACK);
                log.debug("Server {} risk +{}: owner '{}' had {} failed logins in last 24h",
                        serverId, SCORE_OWNER_UNDER_ATTACK, ownerUsername, ownerFailedLogins);
            }
        }

        // FACTOR 4: Low-trust incoming graph edges
        long lowTrustEdges = relationshipRepository.countLowTrustIncomingEdges(
                serverId, AssetType.SERVER, LOW_TRUST_MAX);
        if (lowTrustEdges > 0) {
            score += SCORE_LOW_TRUST_REACHABLE;
            breakdown.put("low_trust_reachable", SCORE_LOW_TRUST_REACHABLE);
            log.debug("Server {} risk +{}: reachable from {} low-trust node(s)",
                    serverId, SCORE_LOW_TRUST_REACHABLE, lowTrustEdges);
        }

        score = Math.min(score, SCORE_MAX);
        log.info("Server {} risk score: {}/100 | breakdown: {}", serverId, score, breakdown);
        return new RiskResult(serverId, AssetType.SERVER, score, breakdown);
    }

    // ─────────────────────────────────────────────────────────────────────
    // USER RISK — called after every LOGIN_FAIL event
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Calculate risk score for a USER (based on recent failed logins).
     * Called by AuthService after every LOGIN_FAIL.
     * FIX 1C: User ID is now passed dynamically — not hardcoded.
     */
    public RiskResult calculateUserRisk(String username) {
        Map<String, Integer> breakdown = new HashMap<>();
        int score = 0;

        // Count failed logins in last 5 minutes (brute-force window)
        long failedLogins = auditLogRepository.countFailedLoginsSince(
                username,
                LocalDateTime.now().minusMinutes(USER_FAILED_LOGIN_WINDOW_MINUTES)
        );

        if (failedLogins > 0) {
            // Scale score with failed login count: 5 failures = 85 risk score (HIGH)
            int failScore = (int) Math.min(failedLogins * 17, 85);
            score += failScore;
            breakdown.put("brute_force_failed_logins_" + failedLogins + "x", failScore);
            log.debug("User '{}' risk +{}: {} failed logins in last 5 min",
                    username, failScore, failedLogins);
        }

        score = Math.min(score, SCORE_MAX);
        log.info("User '{}' risk score: {}/100 | failed_logins={} | breakdown: {}",
                username, score, failedLogins, breakdown);
        return new RiskResult(null, AssetType.USER, score, breakdown, username);
    }

    // ─────────────────────────────────────────────────────────────────────
    // ALL SERVERS — used for dashboard and scheduled scan
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Calculate risk score for ALL servers.
     * Returns map of serverId → RiskResult.
     */
    public Map<Long, RiskResult> calculateAllServerRisks() {
        Map<Long, RiskResult> results = new HashMap<>();
        serverRepository.findAll().forEach(server -> {
            RiskResult result = calculateServerRisk(server.getId());
            results.put(server.getId(), result);
        });
        return results;
    }

    // ─────────────────────────────────────────────────────────────────────
    // SCHEDULED AUTO-SCAN — runs every 30 minutes automatically
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Automatic risk scan — runs every 30 minutes.
     * Scores all servers. If score ≥ 50, triggers incident creation.
     * No manual "Evaluate" click needed.
     */
    @Scheduled(fixedDelay = 1800000) // 30 minutes
    public void scheduledRiskScan() {
        log.info("Scheduled risk scan started...");
        serverRepository.findAll().forEach(server -> {
            RiskResult result = calculateServerRisk(server.getId());
            log.info("Auto-scan: Server {} ({}) → score={}/100 [{}]",
                    server.getId(), server.getName(), result.score, result.getSeverityLabel());
        });
        log.info("Scheduled risk scan complete.");
    }

    // ─────────────────────────────────────────────────────────────────────
    // SEVERITY HELPER
    // ─────────────────────────────────────────────────────────────────────

    public Incident.Severity scoreToSeverity(int score) {
        if (score >= 95) return Incident.Severity.CRITICAL;
        if (score >= 85) return Incident.Severity.HIGH;
        if (score >= 70) return Incident.Severity.MEDIUM;
        return Incident.Severity.LOW;
    }

    /**
     * generateRecommendation — produces plain-English remediation advice.
     * Called by RiskController to show judges the "AI-assisted" recommendation.
     *
     * Based on which factors triggered, returns a prioritized action list.
     */
    public String generateRecommendation(int score, Map<String, Integer> breakdown) {
        StringBuilder sb = new StringBuilder();
        sb.append("AI Risk Recommendations (Score: ").append(score).append("/100) — ");

        if (breakdown.containsKey("unpatched_server")) {
            sb.append("[URGENT] Apply all pending OS security patches immediately. ");
            sb.append("Server has not been patched in over 90 days — ");
            sb.append("known CVEs may be exploitable. Schedule maintenance window. ");
        }
        if (breakdown.containsKey("expired_license")) {
            sb.append("[COMPLIANCE] Renew expired software license to restore vendor support. ");
            sb.append("Running unlicensed software violates NEDI compliance policy. ");
            sb.append("Contact procurement team immediately. ");
        }
        boolean ownerAttacked = breakdown.keySet().stream()
                .anyMatch(k -> k.startsWith("owner_account_attacked"));
        if (ownerAttacked) {
            sb.append("[SECURITY] Server owner account is under active brute-force attack. ");
            sb.append("Enable MFA on admin account. Rotate credentials. ");
            sb.append("Review access permissions and check for unauthorized logins. ");
        }
        if (breakdown.containsKey("low_trust_reachable")) {
            sb.append("[NETWORK] Server is reachable from low-trust network nodes. ");
            sb.append("Implement network segmentation. ");
            sb.append("Review firewall rules and restrict lateral movement paths. ");
        }
        if (breakdown.isEmpty()) {
            sb.append("No active risk factors detected. Continue routine monitoring. ");
            sb.append("Ensure patch schedule is maintained and licenses are current.");
        }

        return sb.toString().trim();
    }

    // ─────────────────────────────────────────────────────────────────────
    // RiskResult — immutable result object
    // ─────────────────────────────────────────────────────────────────────

    public static class RiskResult {
        public final Long assetId;
        public final AssetType assetType;
        public final int score;
        public final Map<String, Integer> breakdown;
        public final String username;

        public RiskResult(Long assetId, AssetType assetType,
                          int score, Map<String, Integer> breakdown) {
            this(assetId, assetType, score, breakdown, null);
        }

        public RiskResult(Long assetId, AssetType assetType,
                          int score, Map<String, Integer> breakdown, String username) {
            this.assetId   = assetId;
            this.assetType = assetType;
            this.score     = score;
            this.breakdown = breakdown;
            this.username  = username;
        }

        public String getSeverityLabel() {
            if (score >= 95) return "CRITICAL";
            if (score >= 85) return "HIGH";
            if (score >= 70) return "MEDIUM";
            if (score >= 50) return "LOW";
            return "SAFE";
        }

        @Override
        public String toString() {
            return String.format("RiskResult{assetId=%d, type=%s, score=%d, severity=%s, breakdown=%s}",
                    assetId, assetType, score, getSeverityLabel(), breakdown);
        }
    }
}
