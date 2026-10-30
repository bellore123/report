package com.cybershield.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * LoadBalancerBackend — a single backend target (usually a server) that
 * a LoadBalancer distributes traffic to. Part of the Load Balancer
 * Management module (PS point 7).
 */
@Entity
@Table(name = "load_balancer_backends", indexes = {
    @Index(name = "idx_backend_lb_id", columnList = "load_balancer_id")
})
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class LoadBalancerBackend {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "load_balancer_id", nullable = false)
    @JsonIgnoreProperties({"backends", "hibernateLazyInitializer", "handler"})
    private LoadBalancer loadBalancer;

    @Column(name = "target_name", nullable = false, length = 100)
    private String targetName;              // e.g. "NEDI-ERP-APP-01"

    @Column(name = "target_ip", length = 45)
    private String targetIp;

    @Builder.Default
    @Column(nullable = false)
    private Integer port = 80;

    // Relative traffic share for WEIGHTED algorithm (ignored otherwise)
    @Builder.Default
    @Column(nullable = false)
    private Integer weight = 1;

    // Result of the most recent health check
    @Builder.Default
    @Column(nullable = false)
    private boolean healthy = true;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }
}
