package com.cybershield.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * AuditLog entity — records EVERY user action across the portal.
 *
 * This table is the central input for:
 *   → Risk Engine (detects brute-force, suspicious patterns)
 *   → Incident Generator (auto-creates incidents on threshold breach)
 *   → Compliance Auditing (who did what and when)
 *
 * Action types: LOGIN_OK, LOGIN_FAIL, CREATE, READ, UPDATE, DELETE
 * Target types: USER, SERVER, FIREWALL, LICENSE, HARDWARE
 */
@Entity
@Table(name = "audit_logs", indexes = {
    @Index(name = "idx_audit_user_id", columnList = "user_id"),
    @Index(name = "idx_audit_timestamp", columnList = "timestamp"),
    @Index(name = "idx_audit_action", columnList = "action")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Which user performed the action (null for anonymous login attempts)
    @Column(name = "user_id")
    private Long userId;

    // What happened: LOGIN_OK, LOGIN_FAIL, CREATE, READ, UPDATE, DELETE
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Action action;

    // What type of asset was targeted
    @Enumerated(EnumType.STRING)
    @Column(name = "target_type", length = 30)
    private TargetType targetType;

    // The ID of the specific asset that was targeted
    @Column(name = "target_asset_id")
    private Long targetAssetId;

    // The username attempted (useful for LOGIN_FAIL where user may not exist)
    @Column(name = "attempted_username", length = 100)
    private String attemptedUsername;

    // Client IP address — used for brute-force detection
    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    // HTTP Request URL / Endpoint (e.g. "POST /api/auth/login", "GET /api/servers")
    @Column(name = "request_url", length = 250)
    private String requestUrl;

    // Optional detail message (e.g. "Password incorrect", "Asset not found")
    @Column(length = 500)
    private String detail;

    @Column(nullable = false)
    private LocalDateTime timestamp;

    @PrePersist
    protected void onCreate() {
        timestamp = LocalDateTime.now();
    }

    public enum Action {
        LOGIN_OK,
        LOGIN_FAIL,
        LOGOUT,
        CREATE,
        READ,
        UPDATE,
        DELETE
    }

    public enum TargetType {
        USER,
        SERVER,
        FIREWALL,
        FIREWALL_RULE,
        LOAD_BALANCER,
        LICENSE,
        HARDWARE,
        INCIDENT
    }
}
