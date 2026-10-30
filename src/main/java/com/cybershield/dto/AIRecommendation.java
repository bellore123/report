package com.cybershield.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * AIRecommendation — Structured explainability model for AI-assisted SOC decisions.
 * Implements NIST AI RMF, NIST CSF 2.0, and MITRE ATT&CK alignment.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AIRecommendation {

    private Long assetId;
    private String assetName;
    private int riskScore;
    private String severity;
    private String executiveSummary;
    private List<String> primaryThreatFactors;
    private List<MitreAttackMapping> mitreAttackMappings;
    private List<String> nistCsfFunctions;
    private List<RemediationAction> prioritizedActions;
    private int projectedScorePostRemediation;
    private String confidenceScore;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class MitreAttackMapping {
        private String techniqueId;
        private String techniqueName;
        private String tactic;
        private String description;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class RemediationAction {
        private String priority; // IMMEDIATE, HIGH, MEDIUM
        private String action;
        private String ownerTeam;
        private String estimatedImpact;
    }
}
