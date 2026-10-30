package com.cybershield.service;

import com.cybershield.model.AssetRelationship;
import com.cybershield.model.AssetRelationship.AssetType;
import com.cybershield.repository.AssetRelationshipRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * AttackPathService — BFS-based attack path prediction.
 *
 * ═══════════════════════════════════════════════════════
 * ALGORITHM EXPLANATION (explain this in your viva!)
 * ═══════════════════════════════════════════════════════
 *
 * WHAT IS BFS?
 *   Breadth-First Search explores a graph level by level.
 *   It guarantees the SHORTEST path (fewest hops) is found first.
 *
 * WHY BFS FOR ATTACK PATHS?
 *   Attackers prefer the shortest route (least effort, least noise).
 *   BFS shows us the same path an attacker would take.
 *
 * HOW IT WORKS HERE:
 *   1. Start node = compromised account (e.g., viewer user, id=3, type=USER)
 *   2. Queue = [startNode]
 *   3. Visited = {startNode}
 *   4. For each node in queue:
 *        → Look up all edges WHERE source = this node
 *        → For each neighbour not yet visited:
 *             - Add to queue
 *             - Record its "parent" (for path reconstruction)
 *             - If this is the TARGET → stop!
 *   5. Reconstruct path: walk parent map from target → start, then reverse
 *
 * RESULT:
 *   [viewer(USER)] → [Firewall-Edge-01(FIREWALL)] → [Server-App-02(SERVER)] → [Server-DB-03(SERVER)]
 *
 * TIME COMPLEXITY: O(V + E) where V = asset nodes, E = relationship edges
 * ═══════════════════════════════════════════════════════
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AttackPathService {

    private final AssetRelationshipRepository relationshipRepository;

    /**
     * Find the shortest attack path from a start node to a target node using BFS.
     *
     * @param startId       ID of the compromised starting asset (e.g., viewer user ID)
     * @param startType     Type of starting asset (USER)
     * @param targetId      ID of the target high-value asset (e.g., Server-DB-03 ID)
     * @param targetType    Type of target (SERVER)
     * @return              AttackPathResult containing the path steps and hop count
     */
    public AttackPathResult findShortestPath(
            Long startId, AssetType startType,
            Long targetId, AssetType targetType) {

        log.info("BFS started: {} {} → {} {}",
                startType, startId, targetType, targetId);

        // ── BFS Data Structures ────────────────────────────────────────────
        // Queue of nodes to visit
        Queue<GraphNode> queue = new LinkedList<>();

        // Visited set: prevents infinite loops in cyclic graphs
        Set<String> visited = new HashSet<>();

        // Parent map: used to reconstruct the path after target is found
        Map<String, String> parentMap = new HashMap<>();

        // ── Initialise BFS ────────────────────────────────────────────────
        GraphNode startNode = new GraphNode(startId, startType);
        queue.add(startNode);
        visited.add(startNode.key());
        parentMap.put(startNode.key(), null); // root has no parent

        boolean found = false;
        GraphNode targetNode = new GraphNode(targetId, targetType);

        // ── BFS Main Loop ─────────────────────────────────────────────────
        while (!queue.isEmpty() && !found) {
            GraphNode current = queue.poll();
            log.debug("BFS exploring node: {}", current.key());

            // Get all edges going OUT from current node
            List<AssetRelationship> edges = relationshipRepository
                    .findBySourceAssetIdAndSourceType(current.id, current.type);

            for (AssetRelationship edge : edges) {
                GraphNode neighbour = new GraphNode(edge.getTargetAssetId(), edge.getTargetType());

                if (!visited.contains(neighbour.key())) {
                    visited.add(neighbour.key());
                    parentMap.put(neighbour.key(), current.key());
                    queue.add(neighbour);

                    log.debug("BFS added to queue: {} (edge trust={})",
                            neighbour.key(), edge.getTrustLevel());

                    // Check if we reached the target
                    if (neighbour.id.equals(targetId) && neighbour.type == targetType) {
                        found = true;
                        log.info("BFS found target: {}", neighbour.key());
                        break;
                    }
                }
            }
        }

        // ── Path Reconstruction ───────────────────────────────────────────
        if (!found) {
            log.warn("BFS: No path found from {} {} to {} {}",
                    startType, startId, targetType, targetId);
            return AttackPathResult.notFound(startId, startType, targetId, targetType);
        }

        // Walk backwards from target using parentMap
        List<String> path = new ArrayList<>();
        String cursor = targetNode.key();
        while (cursor != null) {
            path.add(cursor);
            cursor = parentMap.get(cursor);
        }
        Collections.reverse(path); // start → target

        log.info("BFS completed. Path ({} hops): {}", path.size() - 1, path);
        return new AttackPathResult(startId, startType, targetId, targetType,
                path, path.size() - 1, true);
    }

    /**
     * Find ALL paths reachable from a start node (full graph traversal from start).
     * Used for the dashboard graph view — shows everything a compromised account can reach.
     *
     * @param startId    Starting asset ID
     * @param startType  Starting asset type
     * @return           List of all reachable asset keys in order of discovery
     */
    public List<String> findAllReachableAssets(Long startId, AssetType startType) {
        Queue<GraphNode> queue = new LinkedList<>();
        Set<String> visited = new HashSet<>();
        List<String> reachable = new ArrayList<>();

        GraphNode start = new GraphNode(startId, startType);
        queue.add(start);
        visited.add(start.key());

        while (!queue.isEmpty()) {
            GraphNode current = queue.poll();
            reachable.add(current.key());

            List<AssetRelationship> edges = relationshipRepository
                    .findBySourceAssetIdAndSourceType(current.id, current.type);

            for (AssetRelationship edge : edges) {
                GraphNode neighbour = new GraphNode(edge.getTargetAssetId(), edge.getTargetType());
                if (!visited.contains(neighbour.key())) {
                    visited.add(neighbour.key());
                    queue.add(neighbour);
                }
            }
        }

        log.info("Full BFS from {}:{} — found {} reachable assets",
                startType, startId, reachable.size());
        return reachable;
    }

    // ─────────────────────────────────────────────────────────────────────
    // Inner classes
    // ─────────────────────────────────────────────────────────────────────

    /** A node in the asset graph — (id, type) pair. */
    private static class GraphNode {
        final Long id;
        final AssetType type;

        GraphNode(Long id, AssetType type) {
            this.id   = id;
            this.type = type;
        }

        /** Unique string key for this node — used in visited set and parent map. */
        String key() {
            return type.name() + ":" + id;
        }
    }

    /** Result object returned by findShortestPath(). */
    public static class AttackPathResult {
        public final Long startId;
        public final AssetType startType;
        public final Long targetId;
        public final AssetType targetType;
        public final List<String> path;      // e.g. ["USER:3", "FIREWALL:1", "SERVER:3"]
        public final int hops;               // number of edges traversed
        public final boolean found;
        public final String summary;         // human-readable path string

        public AttackPathResult(Long startId, AssetType startType,
                                Long targetId, AssetType targetType,
                                List<String> path, int hops, boolean found) {
            this.startId   = startId;
            this.startType = startType;
            this.targetId  = targetId;
            this.targetType = targetType;
            this.path      = path;
            this.hops      = hops;
            this.found     = found;
            this.summary   = String.join(" → ", path);
        }

        public static AttackPathResult notFound(Long startId, AssetType startType,
                                                Long targetId, AssetType targetType) {
            return new AttackPathResult(startId, startType, targetId, targetType,
                    Collections.emptyList(), 0, false);
        }
    }
}
