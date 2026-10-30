package com.cybershield.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Incident entity — auto-generated security incident record.
 *
 * Created automatically by IncidentService when:
 *   → Risk score of an asset/user exceeds 70  (MEDIUM)
 *   → Risk score of an asset/user exceeds 85  (HIGH / CRITICAL)
 *
 * This is the "JIRA-style ticket" of the pipeline.
 * During the demo: run an attack → watch this table get a new row.
 *
 * Severity levels:
 *   LOW      → Risk score 50-69  (informational)
 *   MEDIUM   → Risk score 70-84  (investigate)
 *   HIGH     → Risk score 85-94  (urgent)
 *   CRITICAL → Risk score 95-100 (immediate action)
 */
@Entity
@Table(name = "incidents")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class Incident {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 200)
    private String title;

    @Column(length = 1000)
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Severity severity;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private IncidentStatus status;

    // Which asset triggered this incident
    @Column(name = "related_asset_id")
    private Long relatedAssetId;

    @Enumerated(EnumType.STRING)
    @Column(name = "related_asset_type", length = 30)
    private AssetRelationship.AssetType relatedAssetType;

    // The risk score that triggered this incident
    @Column(name = "risk_score")
    private int riskScore;

    // The predicted attack path at time of incident (stored as JSON string)
    @Column(name = "attack_path", length = 2000)
    private String attackPath;

    // Which user was involved (e.g., the user being brute-forced)
    @Column(name = "affected_username", length = 100)
    private String affectedUsername;

    // IP address that triggered the attack
    @Column(name = "source_ip", length = 45)
    private String sourceIp;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "resolved_at")
    private LocalDateTime resolvedAt;

    @Column(name = "resolved_by", length = 100)
    private String resolvedBy;

    @Column(name = "contained_at")
    private LocalDateTime containedAt;

    @Column(name = "contained_by", length = 100)
    private String containedBy;

    @Column(name = "assigned_to", length = 100)
    private String assignedTo;

    @Column(name = "remediation_notes", length = 2000)
    private String remediationNotes;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }

    public enum Severity {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    public enum IncidentStatus {
        OPEN,
        INVESTIGATING,
        CONTAINED,
        RESOLVED,
        FALSE_POSITIVE
    }
}
