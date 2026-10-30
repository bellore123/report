package com.cybershield.controller;

import com.cybershield.model.AuditLog;
import com.cybershield.service.AuditLogService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * AuditLogController — REST API to view audit trail.
 * READ-ONLY — no one can modify audit logs through the API (integrity).
 *
 * Endpoints:
 *   GET /api/audit-logs        → last 50 logs (all users see this)
 *   GET /api/audit-logs/user/{userId} → logs for a specific user (ADMIN only)
 */
@RestController
@RequestMapping("/api/audit-logs")
@RequiredArgsConstructor
public class AuditLogController {

    private final AuditLogService auditLogService;

    // Recent logs — ADMIN, SERVER_ADMIN, and VIEWER can view
    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<List<AuditLog>> getRecentLogs() {
        return ResponseEntity.ok(auditLogService.getRecentLogs());
    }

    // Logs for specific user — ADMIN only
    @GetMapping("/user/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<AuditLog>> getLogsForUser(@PathVariable Long userId) {
        return ResponseEntity.ok(auditLogService.getLogsForUser(userId));
    }
}
