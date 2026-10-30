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
 * Server entity — represents a managed server in the data center.
 *
 * Used by:
 *   → Risk Engine (checks last_patch_date to compute patch score)
 *   → Attack Path graph (servers are nodes in AssetRelationships)
 *   → Dashboard (server count, unpatched count)
 */
@Entity
@Table(name = "servers")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class Server {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 100)
    private String name;

    @Column(nullable = false, length = 45, unique = true)
    private String ipAddress;

    @Column(length = 50)
    private String operatingSystem;        // e.g. "Ubuntu 22.04 LTS"

    @Column(length = 20)
    private String osVersion;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private ServerStatus status;

    @Column(length = 100)
    private String location;               // e.g. "Rack A3, Data Center 1"

    @Column(length = 100)
    private String owner;                  // team or person responsible

    @Column(name = "cpu_cores")
    private Integer cpuCores;

    @Column(name = "ram_gb")
    private Integer ramGb;

    @Column(name = "storage_gb")
    private Integer storageGb;

    // Used by Risk Engine: if older than 90 days → +30 risk points
    @Column(name = "last_patch_date")
    private LocalDate lastPatchDate;

    @Column(name = "warranty_expiry")
    private LocalDate warrantyExpiry;

    @Column(length = 500)
    private String notes;

    /** Maps this server to a NEDI DigitalService (e.g. "EXAM_PORTAL") */
    @Column(name = "service_code", length = 30)
    private String serviceCode;

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

    public enum ServerStatus {
        RUNNING,
        STOPPED,
        MAINTENANCE,
        DECOMMISSIONED
    }
}
