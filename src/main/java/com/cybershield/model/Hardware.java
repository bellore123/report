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
 * Hardware entity — tracks physical data center hardware assets.
 * Covers switches, routers, UPS, racks, cables, storage arrays etc.
 *
 * This is the Hardware Inventory and Asset Tracking module for the
 * NEDI (National Education Digital Infrastructure) demo scenario.
 */
@Entity
@Table(name = "hardware")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class Hardware {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Unique physical asset tag (e.g. "NEDI-SW-001")
    @Column(name = "asset_tag", nullable = false, unique = true, length = 50)
    private String assetTag;

    @Column(nullable = false, length = 100)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(name = "hardware_type", nullable = false, length = 30)
    private HardwareType hardwareType;

    @Column(length = 50)
    private String manufacturer;

    @Column(length = 50)
    private String model;

    @Column(name = "serial_number", length = 100, unique = true)
    private String serialNumber;

    @Column(length = 100)
    private String location;               // e.g. "Rack B2, Slot 4"

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private HardwareStatus status;

    @Column(name = "purchase_date")
    private LocalDate purchaseDate;

    @Column(name = "warranty_expiry")
    private LocalDate warrantyExpiry;

    @Column(name = "last_maintenance_date")
    private LocalDate lastMaintenanceDate;

    @Column(name = "next_maintenance_date")
    private LocalDate nextMaintenanceDate;

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

    public enum HardwareType {
        SWITCH,
        ROUTER,
        LOAD_BALANCER,
        UPS,
        RACK,
        STORAGE_ARRAY,
        PATCH_PANEL,
        CABLE,
        OTHER
    }

    public enum HardwareStatus {
        IN_USE,
        SPARE,
        MAINTENANCE,
        DECOMMISSIONED,
        DISPOSED
    }
}
