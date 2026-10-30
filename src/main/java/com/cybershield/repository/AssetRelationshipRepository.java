package com.cybershield.repository;

import com.cybershield.model.AssetRelationship;
import com.cybershield.model.AssetRelationship.AssetType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * AssetRelationshipRepository — graph edge queries for BFS traversal.
 *
 * The BFS algorithm calls findBySourceAssetIdAndSourceType() repeatedly
 * to expand the frontier one hop at a time from the starting node.
 */
@Repository
public interface AssetRelationshipRepository extends JpaRepository<AssetRelationship, Long> {

    // BFS: get all edges going OUT from a given node
    List<AssetRelationship> findBySourceAssetIdAndSourceType(
            Long sourceAssetId, AssetType sourceType);

    // Risk Engine: is this asset reachable from any low-trust node?
    @Query("SELECT COUNT(r) FROM AssetRelationship r WHERE r.targetAssetId = :assetId " +
           "AND r.targetType = :assetType AND r.trustLevel < :maxTrust")
    long countLowTrustIncomingEdges(
            @Param("assetId") Long assetId,
            @Param("assetType") AssetType assetType,
            @Param("maxTrust") int maxTrust);

    // Get all edges where source is a USER node (for user-initiated attack paths)
    List<AssetRelationship> findBySourceType(AssetType sourceType);
}
