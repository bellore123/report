package com.cybershield.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * FirewallRule entity — NEW MODULE (PS point 6: "set up and monitor
 * network policies, security rules, and traffic management").
 *
 * Previously the Firewall entity only stored a bare `activeRulesCount`
 * number — this gives each firewall an actual, manageable list of rules.
 */
@Entity
@Table(name = "firewall_rules", indexes = {
    @Index(name = "idx_rule_firewall_id", columnList = "firewall_id")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class FirewallRule {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "firewall_id", nullable = false)
    @JsonIgnoreProperties({"rules", "hibernateLazyInitializer", "handler"})
    private Firewall firewall;

    @Column(nullable = false, length = 100)
    private String name;                    // e.g. "Allow HTTPS inbound"

    @Column(name = "source_ip", length = 50)
    private String sourceIp;                // e.g. "0.0.0.0/0" or "10.0.1.0/24"

    @Column(name = "destination_ip", length = 50)
    private String destinationIp;           // e.g. "10.0.2.10"

    @Column(length = 20)
    private String port;                    // e.g. "443", "22", "1000-2000"

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 10)
    private Protocol protocol;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 10)
    private RuleAction action;

    // Lower number = evaluated first (like real firewall rule ordering)
    @Builder.Default
    @Column(nullable = false)
    private Integer priority = 100;

    @Builder.Default
    @Column(nullable = false)
    private boolean enabled = true;

    @Column(length = 300)
    private String description;

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

    public enum Protocol { TCP, UDP, ICMP, ANY }

    public enum RuleAction { ALLOW, DENY }
}
