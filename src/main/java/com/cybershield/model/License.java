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
 * License entity — tracks software licenses for compliance management.
 *
 * Used by:
 *   → Risk Engine: expired license → +25 risk points on linked assets
 *   → Dashboard: expiry alerts (licenses expiring in < 30 days)
 *   → Compliance report: total vs used seat counts
 */
@Entity
@Table(name = "licenses")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class License {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "software_name", nullable = false, length = 100)
    private String softwareName;              // e.g. "Windows Server 2022"

    @Column(length = 50)
    private String vendor;                    // e.g. "Microsoft"

    @Column(name = "license_key", length = 100)
    private String licenseKey;

    @Enumerated(EnumType.STRING)
    @Column(name = "license_type", length = 30)
    private LicenseType licenseType;          // PER_SEAT, SUBSCRIPTION, PERPETUAL

    // Total seats/instances purchased
    @Column(name = "total_seats", nullable = false)
    private Integer totalSeats;

    // Currently allocated/used seats
    @Column(name = "used_seats", nullable = false)
    private Integer usedSeats;

    // Critical field: used by Dashboard for expiry alerts
    @Column(name = "expiry_date", nullable = false)
    private LocalDate expiryDate;

    @Column(name = "purchase_date")
    private LocalDate purchaseDate;

    @Column(name = "renewal_cost")
    private Double renewalCost;

    @Column(name = "assigned_to", length = 100)
    private String assignedTo;               // team or server name

    // Link to specific server — Risk Engine checks per-server expired licenses
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "server_id")
    @JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
    private Server server;                   // null = global/unlinked license

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private LicenseStatus status;

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

    /**
     * Convenience method used by the Risk Engine and Dashboard.
     * Returns true if this license is expired today.
     */
    @Transient
    public boolean isExpired() {
        return expiryDate != null && expiryDate.isBefore(LocalDate.now());
    }

    /**
     * Returns true if the license expires within the next 30 days.
     * Used for dashboard warning alerts.
     */
    @Transient
    public boolean isExpiringSoon() {
        if (expiryDate == null) return false;
        LocalDate thirtyDaysFromNow = LocalDate.now().plusDays(30);
        return !isExpired() && expiryDate.isBefore(thirtyDaysFromNow);
    }

    public enum LicenseType {
        PER_SEAT,
        SUBSCRIPTION,
        PERPETUAL,
        OPEN_SOURCE
    }

    public enum LicenseStatus {
        ACTIVE,
        EXPIRED,
        PENDING_RENEWAL,
        CANCELLED
    }
}
