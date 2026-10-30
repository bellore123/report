package com.cybershield.controller;

import com.cybershield.model.AssetRelationship.AssetType;
import com.cybershield.service.IncidentService;
import com.cybershield.service.RiskEngineService;
import com.cybershield.service.RiskEngineService.RiskResult;
import com.cybershield.service.AIRecommendationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * RiskController — exposes Risk Engine results + AI recommendations.
 *
 * Endpoints:
 *   GET  /api/risk/server/{id}          → risk score + recommendation for one server
 *   GET  /api/risk/servers              → risk scores for ALL servers
 *   GET  /api/risk/user/{username}      → risk score for a user
 *   POST /api/risk/evaluate/server/{id} → evaluate + auto-create incident
 */
@RestController
@RequestMapping("/api/risk")
@RequiredArgsConstructor
public class RiskController {

    private final RiskEngineService       riskEngineService;
    private final IncidentService         incidentService;
    private final AIRecommendationService aiRecommendationService;

    @GetMapping("/server/{id}")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<Map<String, Object>> getServerRisk(@PathVariable Long id) {
        RiskResult result = riskEngineService.calculateServerRisk(id);
        String recommendation = riskEngineService.generateRecommendation(result.score, result.breakdown);
        var structuredAi = aiRecommendationService.generateServerRecommendation(id, result);
        return ResponseEntity.ok(Map.of(
                "assetId",         result.assetId,
                "assetType",       result.assetType,
                "score",           result.score,
                "severity",        result.getSeverityLabel(),
                "breakdown",       result.breakdown,
                "recommendation",  recommendation,
                "aiAnalysis",      structuredAi
        ));
    }

    @GetMapping("/ai-analysis/{id}")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<?> getStructuredAiAnalysis(@PathVariable Long id) {
        RiskResult result = riskEngineService.calculateServerRisk(id);
        return ResponseEntity.ok(aiRecommendationService.generateServerRecommendation(id, result));
    }

    @GetMapping("/servers")
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<Map<Long, Map<String, Object>>> getAllServerRisks() {
        Map<Long, RiskResult> allRisks = riskEngineService.calculateAllServerRisks();
        Map<Long, Map<String, Object>> response = new HashMap<>();
        allRisks.forEach((id, result) -> {
            String recommendation = riskEngineService.generateRecommendation(result.score, result.breakdown);
            response.put(id, Map.of(
                    "score",          result.score,
                    "severity",       result.getSeverityLabel(),
                    "breakdown",      result.breakdown,
                    "recommendation", recommendation
            ));
        });
        return ResponseEntity.ok(response);
    }

    @GetMapping("/user/{username}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getUserRisk(@PathVariable String username) {
        RiskResult result = riskEngineService.calculateUserRisk(username);
        String recommendation = riskEngineService.generateRecommendation(result.score, result.breakdown);
        return ResponseEntity.ok(Map.of(
                "username",       username,
                "assetType",      result.assetType,
                "score",          result.score,
                "severity",       result.getSeverityLabel(),
                "breakdown",      result.breakdown,
                "recommendation", recommendation
        ));
    }

    @PostMapping("/evaluate/server/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> evaluateServer(@PathVariable Long id) {
        var incident = incidentService.evaluateAndCreateServerIncident(id);
        RiskResult result = riskEngineService.calculateServerRisk(id);
        String recommendation = riskEngineService.generateRecommendation(result.score, result.breakdown);

        return ResponseEntity.ok(Map.of(
                "assetId",         id,
                "score",           result.score,
                "severity",        result.getSeverityLabel(),
                "breakdown",       result.breakdown,
                "recommendation",  recommendation,
                "incidentCreated", incident != null,
                "incidentId",      incident != null ? incident.getId() : "none"
        ));
    }
}
