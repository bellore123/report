package com.cybershield;

import com.cybershield.model.AssetRelationship.AssetType;
import com.cybershield.model.Incident;
import com.cybershield.model.Incident.IncidentStatus;
import com.cybershield.model.Incident.Severity;
import com.cybershield.repository.IncidentRepository;
import com.cybershield.security.JwtUtil;
import com.cybershield.service.IncidentService;
import com.cybershield.service.ReportService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * IncidentAndReportTests — Tests incident lifecycle workflow (OPEN -> INVESTIGATING -> CONTAINED -> RESOLVED),
 * remediation note logging, and dynamic JSON/HTML report generation.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class IncidentAndReportTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private IncidentRepository incidentRepository;

    @Autowired
    private IncidentService incidentService;

    @Autowired
    private ReportService reportService;

    @Autowired
    private JwtUtil jwtUtil;

    private Incident testIncident;

    @BeforeEach
    void setUp() {
        testIncident = incidentRepository.save(Incident.builder()
                .title("Unauthorized Access Attempt on NEDI-EXAM-DB-01")
                .description("Suspicious lateral traversal detected targeting national exam database.")
                .severity(Severity.HIGH)
                .status(IncidentStatus.OPEN)
                .relatedAssetId(3L)
                .relatedAssetType(AssetType.SERVER)
                .riskScore(88)
                .attackPath("viewer (USER) → NEDI-DMZ-FW-01 (FIREWALL) → NEDI-EXAM-APP-01 (SERVER) → NEDI-EXAM-DB-01 (SERVER)")
                .affectedUsername("viewer")
                .sourceIp("10.0.0.99")
                .createdAt(LocalDateTime.now())
                .build());
    }

    @Test
    @DisplayName("1. Complete Incident Response Lifecycle: OPEN -> INVESTIGATING -> CONTAINED -> RESOLVED")
    void testIncidentResponseLifecycle() {
        Long id = testIncident.getId();

        // 1. INVESTIGATING
        Incident investigating = incidentService.markInvestigating(id, "analyst-alice");
        assertEquals(IncidentStatus.INVESTIGATING, investigating.getStatus());
        assertEquals("analyst-alice", investigating.getAssignedTo());

        // 2. CONTAINED
        Incident contained = incidentService.containIncident(id, "soc-lead-bob", "Firewall rule applied; DMZ pivot severed");
        assertEquals(IncidentStatus.CONTAINED, contained.getStatus());
        assertEquals("soc-lead-bob", contained.getContainedBy());
        assertNotNull(contained.getContainedAt());
        assertTrue(contained.getRemediationNotes().contains("Firewall rule applied"));

        // 3. REMEDIATION NOTES
        Incident withNotes = incidentService.updateRemediationNotes(id, "Host memory dump collected and verified clean.");
        assertTrue(withNotes.getRemediationNotes().contains("Host memory dump collected"));

        // 4. RESOLVED
        Incident resolved = incidentService.resolveIncident(id, "admin", "Patch applied and credentials rotated");
        assertEquals(IncidentStatus.RESOLVED, resolved.getStatus());
        assertEquals("admin", resolved.getResolvedBy());
        assertNotNull(resolved.getResolvedAt());
    }

    @Test
    @DisplayName("2. ReportService produces comprehensive structured JSON report")
    void testReportServiceJsonGeneration() {
        Map<String, Object> report = reportService.generateIncidentReportJson(testIncident.getId());

        assertNotNull(report);
        assertTrue(report.containsKey("reportId"));
        assertTrue(report.containsKey("incident"));
        assertTrue(report.containsKey("affectedAsset"));
        assertTrue(report.containsKey("riskBreakdown"));
        assertTrue(report.containsKey("aiRecommendation"));
        assertTrue(report.containsKey("attackPathNodes"));
        assertTrue(report.containsKey("complianceAttestations"));

        @SuppressWarnings("unchecked")
        Map<String, Object> inc = (Map<String, Object>) report.get("incident");
        assertEquals(testIncident.getId(), inc.get("id"));
        assertEquals(88, inc.get("riskScore"));
    }

    @Test
    @DisplayName("3. ReportService produces printable executive HTML document")
    void testReportServiceHtmlGeneration() {
        String html = reportService.generateIncidentReportHtml(testIncident.getId());

        assertNotNull(html);
        assertTrue(html.contains("<!DOCTYPE html>"), "Must be valid HTML document");
        assertTrue(html.contains("CYBERSHIELD NEXUS // INCIDENT REPORT"), "Must have header");
        assertTrue(html.contains("MITRE ATT&CK"), "Must include MITRE section");
        assertTrue(html.contains("NIST CSF"), "Must include NIST CSF functions");
        assertTrue(html.contains("window.print()"), "Must include print action");
    }

    @Test
    @DisplayName("4. ReportController REST endpoints return valid JSON and HTML with JWT")
    void testReportControllerEndpoints() throws Exception {
        String adminToken = jwtUtil.generateToken("admin", "ADMIN");

        // JSON endpoint test
        mockMvc.perform(get("/api/reports/incident/" + testIncident.getId())
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.reportId").exists())
                .andExpect(jsonPath("$.incident.title").value(testIncident.getTitle()));

        // HTML endpoint test with query token parameter
        mockMvc.perform(get("/api/reports/incident/" + testIncident.getId() + "/html")
                        .param("token", adminToken))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("CYBERSHIELD NEXUS")));
    }
}
