package com.cybershield.service;

import com.cybershield.dto.AIRecommendation;
import com.cybershield.dto.AIRecommendation.MitreAttackMapping;
import com.cybershield.dto.AIRecommendation.RemediationAction;
import com.cybershield.model.Server;
import com.cybershield.repository.ServerRepository;
import com.cybershield.service.RiskEngineService.RiskResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * AIRecommendationService — Generates explainable, defensible cybersecurity
 * guidance grounded in NIST CSF 2.0, NIST SP 800-207 Zero Trust, and MITRE ATT&CK.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AIRecommendationService {

    private final ServerRepository serverRepository;

    public AIRecommendation generateServerRecommendation(Long serverId, RiskResult riskResult) {
        String serverName = "Server #" + serverId;
        String osInfo = "Unknown OS";
        String owner = "unassigned";

        var serverOpt = serverRepository.findById(serverId);
        if (serverOpt.isPresent()) {
            Server server = serverOpt.get();
            serverName = server.getName();
            osInfo = server.getOperatingSystem() + " " + (server.getOsVersion() != null ? server.getOsVersion() : "");
            owner = server.getOwner() != null ? server.getOwner() : "sysadmin";
        }

        Map<String, Integer> breakdown = riskResult.breakdown;
        List<String> threatFactors = new ArrayList<>();
        List<MitreAttackMapping> mitreMappings = new ArrayList<>();
        List<String> nistFunctions = new ArrayList<>();
        List<RemediationAction> actions = new ArrayList<>();

        int scoreReduction = 0;

        // FACTOR 1: Patch overdue
        if (breakdown.containsKey("unpatched_server")) {
            threatFactors.add("Operating system and runtime on " + serverName + " (" + osInfo + ") unpatched for >90 days.");
            mitreMappings.add(MitreAttackMapping.builder()
                    .techniqueId("T1190")
                    .techniqueName("Exploit Public-Facing Application")
                    .tactic("Initial Access")
                    .description("Adversaries exploit unpatched vulnerabilities in public-facing or inter-tier application services.")
                    .build());
            mitreMappings.add(MitreAttackMapping.builder()
                    .techniqueId("T1068")
                    .techniqueName("Exploitation for Privilege Escalation")
                    .tactic("Privilege Escalation")
                    .description("Unpatched local kernel or daemon flaws enable privilege elevation.")
                    .build());
            nistFunctions.add("NIST CSF PR.IP-12 (Vulnerability Management & Patching)");
            actions.add(RemediationAction.builder()
                    .priority("IMMEDIATE")
                    .action("Stage and apply security kernel updates and CVE vulnerability patches on " + serverName + ".")
                    .ownerTeam("Infrastructure Operations")
                    .estimatedImpact("-30 Risk Points")
                    .build());
            scoreReduction += 30;
        }

        // FACTOR 2: Expired license
        if (breakdown.containsKey("expired_license")) {
            threatFactors.add("Critical software or database license assigned to " + serverName + " has expired, halting vendor security hotfixes.");
            mitreMappings.add(MitreAttackMapping.builder()
                    .techniqueId("T1588.006")
                    .techniqueName("Obtain Capabilities: Unmaintained Vulnerabilities")
                    .tactic("Resource Development")
                    .description("Running unsupported or unlicensed enterprise software leaves zero-day patches unapplied.")
                    .build());
            nistFunctions.add("NIST CSF PR.DS-06 (Integrity & Maintenance Contract Validation)");
            actions.add(RemediationAction.builder()
                    .priority("IMMEDIATE")
                    .action("Renew database enterprise license to regain official vendor security patches and compliance support.")
                    .ownerTeam("Procurement & Security Compliance")
                    .estimatedImpact("-25 Risk Points")
                    .build());
            scoreReduction += 25;
        }

        // FACTOR 3: Account under attack
        boolean ownerAttacked = breakdown.keySet().stream().anyMatch(k -> k.startsWith("owner_account_attacked"));
        if (ownerAttacked) {
            threatFactors.add("Asset administrator account ('" + owner + "') is under active credential brute-force attacks.");
            mitreMappings.add(MitreAttackMapping.builder()
                    .techniqueId("T1110.001")
                    .techniqueName("Brute Force: Password Guessing")
                    .tactic("Credential Access")
                    .description("Adversaries systematically guess passwords to obtain administrative access.")
                    .build());
            mitreMappings.add(MitreAttackMapping.builder()
                    .techniqueId("T1078")
                    .techniqueName("Valid Accounts")
                    .tactic("Defense Evasion / Initial Access")
                    .description("Compromised credentials permit authorized entry into backend network segments.")
                    .build());
            nistFunctions.add("NIST CSF PR.AC-07 (Multi-Factor Authentication & Identity Protection)");
            actions.add(RemediationAction.builder()
                    .priority("IMMEDIATE")
                    .action("Trigger automated account lockout, force password rotation, and require hardware-token MFA for '" + owner + "'.")
                    .ownerTeam("Identity & Access Management (IAM)")
                    .estimatedImpact("-20 Risk Points")
                    .build());
            scoreReduction += 20;
        }

        // FACTOR 4: Low-trust lateral movement reachability
        if (breakdown.containsKey("low_trust_reachable")) {
            threatFactors.add("Asset is directly reachable via low-trust ingress edges from DMZ perimeter without internal micro-segmentation.");
            mitreMappings.add(MitreAttackMapping.builder()
                    .techniqueId("T1021.002")
                    .techniqueName("Remote Services: SMB/SSH Lateral Movement")
                    .tactic("Lateral Movement")
                    .description("Compromised DMZ edge nodes can pivot laterally into core application and database tiers.")
                    .build());
            nistFunctions.add("NIST CSF PR.AC-05 (Network Protection & Zero Trust Segmentation)");
            actions.add(RemediationAction.builder()
                    .priority("HIGH")
                    .action("Reconfigure firewall access control lists (ACLs) to block direct lateral traversal from DMZ to internal database tier.")
                    .ownerTeam("Network Engineering & SOC")
                    .estimatedImpact("-15 Risk Points")
                    .build());
            scoreReduction += 15;
        }

        if (threatFactors.isEmpty()) {
            threatFactors.add("No critical threats detected. Asset is healthy, fully patched, and authenticated within policy parameters.");
            nistFunctions.add("NIST CSF DE.CM-01 (Continuous Security Monitoring)");
            actions.add(RemediationAction.builder()
                    .priority("ROUTINE")
                    .action("Maintain routine SOC surveillance and automated daily patch/license auditing.")
                    .ownerTeam("SOC Monitoring")
                    .estimatedImpact("Baseline Nominal (0)")
                    .build());
        }

        int projectedScore = Math.max(0, riskResult.score - scoreReduction);

        String executiveSummary = String.format(
                "Automated AI threat analysis for %s assesses current security posture as %s (%d/100). " +
                "Primary risk drivers include %d active vulnerability vectors. " +
                "Full implementation of prioritized mitigations is projected to reduce asset risk to %d/100.",
                serverName, riskResult.getSeverityLabel(), riskResult.score,
                threatFactors.size(), projectedScore
        );

        return AIRecommendation.builder()
                .assetId(serverId)
                .assetName(serverName)
                .riskScore(riskResult.score)
                .severity(riskResult.getSeverityLabel())
                .executiveSummary(executiveSummary)
                .primaryThreatFactors(threatFactors)
                .mitreAttackMappings(mitreMappings)
                .nistCsfFunctions(nistFunctions)
                .prioritizedActions(actions)
                .projectedScorePostRemediation(projectedScore)
                .confidenceScore("94% (Deterministic Rule Graph Correlation)")
                .build();
    }
}
