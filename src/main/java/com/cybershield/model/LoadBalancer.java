package com.cybershield.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * LoadBalancer entity — NEW MODULE (PS point 7: "configuration,
 * monitoring, and scaling of load balancers... optimal performance,
 * high availability, and efficient resource utilization").
 *
 * Previously load balancers only existed as a generic HardwareType tag
 * inside the Hardware inventory — this gives them their own dedicated
 * configuration: distribution algorithm, health checks, and a live
 * backend server pool (see LoadBalancerBackend).
 */
@Entity
@Table(name = "load_balancers")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class LoadBalancer {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 100)
    private String name;

    @Column(name = "virtual_ip", length = 45)
    private String virtualIp;               // the single IP clients connect to

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Algorithm algorithm;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private LbStatus status;

    @Column(name = "health_check_path", length = 200)
    private String healthCheckPath;         // e.g. "/actuator/health"

    @Builder.Default
    @Column(name = "health_check_interval_seconds", nullable = false)
    private Integer healthCheckIntervalSeconds = 30;

    @Column(length = 300)
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

    public enum Algorithm { ROUND_ROBIN, LEAST_CONNECTIONS, IP_HASH, WEIGHTED }

    public enum LbStatus { ACTIVE, INACTIVE, MAINTENANCE, DEGRADED }
}
