package com.cybershield.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * AssetRelationship — one directed edge in the asset graph.
 *
 * This table is the backbone of the Attack Path module.
 * Each row says: "source_asset CAN REACH target_asset via this relationship."
 *
 * Example rows:
 *   USER(viewer_account) --CONNECTS_TO--> FIREWALL(Firewall-Edge-01)  trust=20
 *   FIREWALL(Edge-01)    --CONNECTS_TO--> SERVER(Server-App-02)        trust=50
 *   SERVER(App-02)       --CONNECTS_TO--> SERVER(Server-DB-03)         trust=60
 *
 * BFS traversal reads these edges to find:
 *   "If viewer is compromised, what is the shortest path to Server-DB-03?"
 *
 * trust_level (0-100):
 *   0-30  = low trust (attacker can traverse easily)
 *   31-70 = medium trust
 *   71-100 = high trust (hard to traverse, strong auth required)
 */
@Entity
@Table(name = "asset_relationships")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
public class AssetRelationship {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Source node
    @Column(name = "source_asset_id", nullable = false)
    private Long sourceAssetId;

    @Enumerated(EnumType.STRING)
    @Column(name = "source_type", nullable = false, length = 30)
    private AssetType sourceType;

    // Target node
    @Column(name = "target_asset_id", nullable = false)
    private Long targetAssetId;

    @Enumerated(EnumType.STRING)
    @Column(name = "target_type", nullable = false, length = 30)
    private AssetType targetType;

    // Relationship type — what kind of connection is this
    @Enumerated(EnumType.STRING)
    @Column(name = "relationship_type", nullable = false, length = 30)
    private RelationshipType relationshipType;

    /**
     * Trust level (0-100).
     * Lower value = easier for attacker to traverse this edge.
     * Risk Engine uses this: if asset reachable from trust<30 node → +15 risk pts
     */
    @Column(name = "trust_level", nullable = false)
    private int trustLevel;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }

    public enum AssetType {
        USER,
        SERVER,
        FIREWALL,
        LICENSE,
        HARDWARE,
        LOAD_BALANCER
    }

    public enum RelationshipType {
        CONNECTS_TO,    // network-level connection (most common)
        MANAGES,        // admin/management relationship
        HOSTS,          // server hosts a service/license
        DEPENDS_ON,     // software dependency
        AUTHENTICATES_TO // auth relationship (user → service)
    }
}
