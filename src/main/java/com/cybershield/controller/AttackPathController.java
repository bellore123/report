package com.cybershield.controller;

import com.cybershield.model.AssetRelationship.AssetType;
import com.cybershield.service.AttackPathService;
import com.cybershield.service.AttackPathService.AttackPathResult;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * AttackPathController — BFS attack path prediction API.
 *
 * Endpoints:
 *   GET /api/graph/attack-path?startId=&startType=&targetId=&targetType=
 *       → Runs BFS and returns shortest path
 *
 *   GET /api/graph/reachable?startId=&startType=
 *       → Returns ALL assets reachable from a starting node
 *
 * Demo usage:
 *   GET /api/graph/attack-path?startId=3&startType=USER&targetId=3&targetType=SERVER
 *   → Returns: ["USER:3", "FIREWALL:1", "SERVER:2", "SERVER:3"]
 *   → Meaning: viewer → Firewall-Edge-01 → Server-App-02 → Server-DB-03
 */
@RestController
@RequestMapping("/api/graph")
@RequiredArgsConstructor
public class AttackPathController {

    private final AttackPathService attackPathService;

    @GetMapping("/attack-path")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<Map<String, Object>> getAttackPath(
            @RequestParam Long startId,
            @RequestParam String startType,
            @RequestParam Long targetId,
            @RequestParam String targetType) {

        AssetType start  = AssetType.valueOf(startType.toUpperCase());
        AssetType target = AssetType.valueOf(targetType.toUpperCase());

        AttackPathResult result = attackPathService.findShortestPath(
                startId, start, targetId, target);

        return ResponseEntity.ok(Map.of(
                "found",        result.found,
                "hops",         result.hops,
                "path",         result.path,
                "summary",      result.summary,
                "startId",      startId,
                "startType",    startType,
                "targetId",     targetId,
                "targetType",   targetType
        ));
    }

    @GetMapping("/reachable")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<Map<String, Object>> getReachableAssets(
            @RequestParam Long startId,
            @RequestParam String startType) {

        AssetType type = AssetType.valueOf(startType.toUpperCase());
        List<String> reachable = attackPathService.findAllReachableAssets(startId, type);

        return ResponseEntity.ok(Map.of(
                "startId",    startId,
                "startType",  startType,
                "reachable",  reachable,
                "totalCount", reachable.size()
        ));
    }
}
