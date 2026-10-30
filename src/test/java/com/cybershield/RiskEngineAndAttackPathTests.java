package com.cybershield;

import com.cybershield.dto.AIRecommendation;
import com.cybershield.model.AssetRelationship.AssetType;
import com.cybershield.model.Server;
import com.cybershield.model.User;
import com.cybershield.repository.ServerRepository;
import com.cybershield.repository.UserRepository;
import com.cybershield.service.AIRecommendationService;
import com.cybershield.service.AttackPathService;
import com.cybershield.service.AttackPathService.AttackPathResult;
import com.cybershield.service.RiskEngineService;
import com.cybershield.service.RiskEngineService.RiskResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.*;

/**
 * RiskEngineAndAttackPathTests — Tests multi-factor risk calculation,
 * BFS lateral movement prediction, and explainable AI recommendations.
 */
@SpringBootTest
@ActiveProfiles("test")
class RiskEngineAndAttackPathTests {

    @Autowired
    private RiskEngineService riskEngineService;

    @Autowired
    private AttackPathService attackPathService;

    @Autowired
    private AIRecommendationService aiRecommendationService;

    @Autowired
    private ServerRepository serverRepository;

    @Autowired
    private UserRepository userRepository;

    @Test
    @DisplayName("1. Server Risk Engine correctly applies multi-factor scoring")
    void testServerRiskScoring() {
        Server examDb = serverRepository.findByName("NEDI-EXAM-DB-01").orElseThrow();
        RiskResult dbResult = riskEngineService.calculateServerRisk(examDb.getId());

        // Exam DB is unpatched (>90d) and has expired Oracle license (+25)
        assertTrue(dbResult.score >= 55, "Exam DB risk score should be at least 55, was: " + dbResult.score);
        assertTrue(dbResult.breakdown.containsKey("unpatched_server"), "Should contain unpatched_server factor");
        assertTrue(dbResult.breakdown.containsKey("expired_license"), "Should contain expired_license factor");
        assertEquals(30, dbResult.breakdown.get("unpatched_server"));
        assertEquals(25, dbResult.breakdown.get("expired_license"));
    }

    @Test
    @DisplayName("2. Patched server has lower risk score than unpatched server")
    void testPatchedVsUnpatchedServerRisk() {
        Server studentWeb = serverRepository.findByName("NEDI-STUDENT-WEB-01").orElseThrow();
        Server examApp = serverRepository.findByName("NEDI-EXAM-APP-01").orElseThrow();

        RiskResult webResult = riskEngineService.calculateServerRisk(studentWeb.getId());
        RiskResult appResult = riskEngineService.calculateServerRisk(examApp.getId());

        assertFalse(webResult.breakdown.containsKey("unpatched_server"), "Recently patched student web should not have patch penalty");
        assertTrue(appResult.breakdown.containsKey("unpatched_server"), "Exam app unpatched >120 days must have patch penalty");
        assertTrue(appResult.score > webResult.score, "Unpatched exam app must have strictly higher risk score");
    }

    @Test
    @DisplayName("3. BFS shortest path traverses from compromised user to high-value database")
    void testBfsAttackPathTraversal() {
        User viewer = userRepository.findByUsername("viewer").orElseThrow();
        Server examDb = serverRepository.findByName("NEDI-EXAM-DB-01").orElseThrow();

        AttackPathResult path = attackPathService.findShortestPath(
                viewer.getId(), AssetType.USER,
                examDb.getId(), AssetType.SERVER
        );

        assertTrue(path.found, "BFS should find lateral movement attack path to Exam DB");
        assertTrue(path.hops >= 2, "Path should require at least 2 hops through perimeter / pivots");
        assertNotNull(path.path);
        assertFalse(path.path.isEmpty());
    }

    @Test
    @DisplayName("4. Explainable AI service produces grounded MITRE ATT&CK and NIST CSF guidance")
    void testExplainableAiRecommendation() {
        Server examDb = serverRepository.findByName("NEDI-EXAM-DB-01").orElseThrow();
        RiskResult dbResult = riskEngineService.calculateServerRisk(examDb.getId());

        AIRecommendation rec = aiRecommendationService.generateServerRecommendation(examDb.getId(), dbResult);

        assertNotNull(rec);
        assertEquals(examDb.getId(), rec.getAssetId());
        assertFalse(rec.getMitreAttackMappings().isEmpty(), "MITRE mappings must not be empty");
        assertFalse(rec.getNistCsfFunctions().isEmpty(), "NIST CSF functions must not be empty");
        assertFalse(rec.getPrioritizedActions().isEmpty(), "Remediation actions must not be empty");

        // Verify MITRE techniques mapped to unpatched server and expired license
        boolean hasExploitPublicFacing = rec.getMitreAttackMappings().stream()
                .anyMatch(m -> "T1190".equals(m.getTechniqueId()));
        boolean hasUnmaintainedVuln = rec.getMitreAttackMappings().stream()
                .anyMatch(m -> "T1588.006".equals(m.getTechniqueId()));

        assertTrue(hasExploitPublicFacing, "Should include MITRE T1190 for unpatched server");
        assertTrue(hasUnmaintainedVuln, "Should include MITRE T1588.006 for expired license");
    }
}
