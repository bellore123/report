package com.cybershield.service;

import com.cybershield.model.AuditLog;
import com.cybershield.model.AuditLog.Action;
import com.cybershield.model.AuditLog.TargetType;
import com.cybershield.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * AuditLogService — THE single entry point for writing audit records.
 *
 * IMPORTANT: Every module (Auth, Server, Firewall, License, Hardware)
 * MUST call this service to log actions. Never write to AuditLogs directly.
 * This ensures consistent, queryable audit data for the Risk Engine.
 *
 * Usage examples:
 *   auditLogService.logLogin(null, "john", "192.168.1.1", false);     // failed login
 *   auditLogService.logLogin(userId, "john", "192.168.1.1", true);    // success
 *   auditLogService.log(userId, Action.UPDATE, TargetType.SERVER, 5L, ip, "Updated OS version");
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuditLogService {

    private final AuditLogRepository auditLogRepository;

    /**
     * Log any generic action (with auto-derived URL).
     */
    public AuditLog log(Long userId, Action action, TargetType targetType,
                        Long targetId, String ipAddress, String detail) {
        String defaultUrl = deriveUrl(action, targetType, targetId);
        return log(userId, action, targetType, targetId, ipAddress, detail, defaultUrl);
    }

    /**
     * Log any generic action with explicit request URL.
     *
     * @param userId       The user performing the action (null for anonymous)
     * @param action       What happened (CREATE, READ, UPDATE, DELETE, etc.)
     * @param targetType   What type of entity was targeted
     * @param targetId     The ID of the specific entity targeted
     * @param ipAddress    Client IP address
     * @param detail       Optional human-readable detail
     * @param requestUrl   Endpoint / URL path invoked
     */
    public AuditLog log(Long userId, Action action, TargetType targetType,
                        Long targetId, String ipAddress, String detail, String requestUrl) {
        AuditLog entry = AuditLog.builder()
                .userId(userId)
                .action(action)
                .targetType(targetType)
                .targetAssetId(targetId)
                .ipAddress(ipAddress)
                .requestUrl(requestUrl)
                .detail(detail)
                .build();

        AuditLog saved = auditLogRepository.save(entry);
        log.debug("AUDIT: user={} action={} target={}/{} url={} ip={}",
                userId, action, targetType, targetId, requestUrl, ipAddress);
        return saved;
    }

    private String deriveUrl(Action action, TargetType targetType, Long targetId) {
        if (targetType == null) return "/api";
        String base;
        switch (targetType) {
            case SERVER: base = "/api/servers"; break;
            case FIREWALL: base = "/api/firewalls"; break;
            case FIREWALL_RULE: base = "/api/firewall-rules"; break;
            case LOAD_BALANCER: base = "/api/loadbalancers"; break;
            case USER: base = "/api/users"; break;
            case LICENSE: base = "/api/licenses"; break;
            case HARDWARE: base = "/api/hardware"; break;
            case INCIDENT: base = "/api/incidents"; break;
            default: base = "/api/assets"; break;
        }
        String method = (action == Action.CREATE) ? "POST "
                      : (action == Action.DELETE) ? "DELETE "
                      : (action == Action.UPDATE) ? "PUT "
                      : "GET ";
        return method + base + (targetId != null && action != Action.CREATE ? "/" + targetId : "");
    }

    /**
     * Convenience method specifically for login events.
     *
     * @param userId          The authenticated user's ID (null if login failed)
     * @param attemptedUsername The username that was attempted
     * @param ipAddress       Client IP address
     * @param success         true = LOGIN_OK, false = LOGIN_FAIL
     */
    public AuditLog logLogin(Long userId, String attemptedUsername,
                             String ipAddress, boolean success) {
        Action action = success ? Action.LOGIN_OK : Action.LOGIN_FAIL;

        AuditLog entry = AuditLog.builder()
                .userId(userId)
                .action(action)
                .targetType(TargetType.USER)
                .targetAssetId(userId)
                .attemptedUsername(attemptedUsername)
                .ipAddress(ipAddress)
                .requestUrl("POST /api/auth/login")
                .detail(success ? "Login successful" : "Invalid credentials")
                .build();

        AuditLog saved = auditLogRepository.save(entry);
        log.debug("AUDIT: LOGIN {} for user='{}' from ip={}",
                success ? "SUCCESS" : "FAILURE", attemptedUsername, ipAddress);
        return saved;
    }

    /**
     * Get recent audit logs (for dashboard display and audit trail).
     */
    public List<AuditLog> getRecentLogs() {
        return auditLogRepository.findTop100ByOrderByTimestampDesc();
    }

    /**
     * Get all logs for a specific user (for user audit trail page).
     */
    public List<AuditLog> getLogsForUser(Long userId) {
        return auditLogRepository.findByUserIdOrderByTimestampDesc(userId);
    }
}
