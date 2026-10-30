package com.cybershield.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * DigitalService — represents one of the 8 NEDI digital services.
 *
 * Each service (e.g. Exam Portal) maps to backend servers via the
 * Server.serviceCode field. The dashboard shows per-service health
 * status derived from the risk scores of its underlying servers.
 */
@Entity
@Table(name = "digital_services")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class DigitalService {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Short machine code used to join with Server.serviceCode */
    @Column(name = "service_code", nullable = false, unique = true, length = 30)
    private String serviceCode;

    /** Human-readable name shown in the dashboard */
    @Column(nullable = false, length = 100)
    private String name;

    /** Brief description for the UI */
    @Column(length = 300)
    private String description;

    /** Internal hostname used for the demo scenario */
    @Column(name = "host_domain", length = 100)
    private String hostDomain;

    /** Institution or central NEDI unit that owns this service */
    @Column(name = "institution_code", length = 30)
    private String institutionCode;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private ServiceStatus status;

    @Enumerated(EnumType.STRING)
    @Column(name = "service_type", nullable = false, length = 30)
    private ServiceType serviceType;

    /** Criticality weight — higher = more important to the org */
    @Column(name = "criticality_level")
    private int criticalityLevel; // 1-5, 5 = highest

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

    public enum ServiceStatus {
        HEALTHY,
        DEGRADED,
        HIGH_RISK,
        DOWN
    }

    public enum ServiceType {
        STUDENT_PORTAL,
        FACULTY_PORTAL,
        EXAM_PORTAL,
        ERP,
        ADMISSION_PORTAL,
        DIGITAL_LIBRARY,
        LMS,
        MAIL_SERVICE
    }
}
