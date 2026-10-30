package com.cybershield.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalDateTime;

/**
 * Firewall entity — represents a managed firewall/network security device.
 *
 * Used by:
 *   → Risk Engine (outdated firmware → risk score increase)
 *   → Attack Path graph (firewalls are nodes — can be pivot points)
 *   → Dashboard (firewall health overview)
 */
@Entity
@Table(name = "firewalls")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class Firewall {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 100)
    private String name;

    @Column(length = 50)
    private String vendor;                  // e.g. "Cisco", "Palo Alto", "Fortinet"

    @Column(length = 50)
    private String model;                   // e.g. "ASA 5505"

    @Column(name = "ip_address", length = 45)
    private String ipAddress;

    @Column(name = "firmware_version", length = 50)
    private String firmwareVersion;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private FirewallStatus status;

    @Column(length = 100)
    private String location;

    // Number of active rules on this firewall (informational)
    @Column(name = "active_rules_count")
    private Integer activeRulesCount;

    // Last time rules were reviewed/updated
    @Column(name = "last_rule_review_date")
    private LocalDate lastRuleReviewDate;

    // Last firmware update date — used by Risk Engine
    @Column(name = "last_firmware_update")
    private LocalDate lastFirmwareUpdate;

    @Column(name = "warranty_expiry")
    private LocalDate warrantyExpiry;

    @Column(length = 500)
    private String notes;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    public enum FirewallStatus {
        ACTIVE,
        INACTIVE,
        MAINTENANCE,
        COMPROMISED
    }
}
