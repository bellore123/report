package com.cybershield.service;

import com.cybershield.dto.AIRecommendation;
import com.cybershield.dto.AIRecommendation.MitreAttackMapping;
import com.cybershield.dto.AIRecommendation.RemediationAction;
import com.cybershield.model.AssetRelationship.AssetType;
import com.cybershield.model.Incident;
import com.cybershield.model.Server;
import com.cybershield.model.User;
import com.cybershield.repository.IncidentRepository;
import com.cybershield.repository.ServerRepository;
import com.cybershield.repository.UserRepository;
import com.cybershield.service.RiskEngineService.RiskResult;
import com.openhtmltopdf.pdfboxout.PdfRendererBuilder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * ReportService — Generates live, dynamic executive incident reports in both
 * JSON (for API integrations & SIEM) and printable HTML (for audits & viva defense).
 *
 * Grounded in:
 *   - NIST Cybersecurity Framework (CSF 2.0)
 *   - MITRE ATT&CK Enterprise Matrix
 *   - Zero Trust Architecture (NIST SP 800-207)
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ReportService {

    private final IncidentRepository incidentRepository;
    private final ServerRepository serverRepository;
    private final UserRepository userRepository;
    private final RiskEngineService riskEngineService;
    private final AIRecommendationService aiRecommendationService;

    private static final DateTimeFormatter ISO_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    /**
     * Generate structured JSON data for an incident report.
     */
    public Map<String, Object> generateIncidentReportJson(Long incidentId) {
        Incident incident = incidentRepository.findById(incidentId)
                .orElseThrow(() -> new NoSuchElementException("Incident not found with ID: " + incidentId));

        Map<String, Object> report = new LinkedHashMap<>();
        report.put("reportId", "NEDI-INC-" + String.format("%04d", incident.getId()));
        report.put("generatedAt", LocalDateTime.now().format(ISO_FMT));
        report.put("classification", "OFFICIAL USE ONLY // NEDI ACADEMIC SOC SIMULATION");
        report.put("infrastructure", "National Education Digital Infrastructure (NEDI)");

        // Incident core data
        Map<String, Object> incidentData = new LinkedHashMap<>();
        incidentData.put("id", incident.getId());
        incidentData.put("title", incident.getTitle());
        incidentData.put("description", incident.getDescription());
        incidentData.put("severity", incident.getSeverity());
        incidentData.put("status", incident.getStatus());
        incidentData.put("riskScore", incident.getRiskScore());
        incidentData.put("sourceIp", incident.getSourceIp() != null ? incident.getSourceIp() : "10.0.0.99");
        incidentData.put("createdAt", incident.getCreatedAt() != null ? incident.getCreatedAt().format(ISO_FMT) : "N/A");
        incidentData.put("containedAt", incident.getContainedAt() != null ? incident.getContainedAt().format(ISO_FMT) : null);
        incidentData.put("containedBy", incident.getContainedBy());
        incidentData.put("resolvedAt", incident.getResolvedAt() != null ? incident.getResolvedAt().format(ISO_FMT) : null);
        incidentData.put("resolvedBy", incident.getResolvedBy());
        incidentData.put("assignedTo", incident.getAssignedTo());
        incidentData.put("remediationNotes", incident.getRemediationNotes());
        report.put("incident", incidentData);

        // Asset correlation & AI Risk assessment
        Map<String, Object> assetDetails = new LinkedHashMap<>();
        AIRecommendation recommendation;
        Map<String, Integer> riskBreakdown = new HashMap<>();

        if (incident.getRelatedAssetType() == AssetType.SERVER && incident.getRelatedAssetId() != null) {
            Optional<Server> serverOpt = serverRepository.findById(incident.getRelatedAssetId());
            if (serverOpt.isPresent()) {
                Server s = serverOpt.get();
                assetDetails.put("type", "SERVER");
                assetDetails.put("id", s.getId());
                assetDetails.put("name", s.getName());
                assetDetails.put("ipAddress", s.getIpAddress());
                assetDetails.put("operatingSystem", s.getOperatingSystem() + " " + (s.getOsVersion() != null ? s.getOsVersion() : ""));
                assetDetails.put("serviceCode", s.getServiceCode() != null ? s.getServiceCode() : "NEDI-CORE");
                assetDetails.put("owner", s.getOwner());
                assetDetails.put("status", s.getStatus());
                assetDetails.put("lastPatchDate", s.getLastPatchDate() != null ? s.getLastPatchDate().toString() : "Never");
            }
            RiskResult riskResult = riskEngineService.calculateServerRisk(incident.getRelatedAssetId());
            riskBreakdown = riskResult.breakdown;
            recommendation = aiRecommendationService.generateServerRecommendation(incident.getRelatedAssetId(), riskResult);
        } else {
            String uname = incident.getAffectedUsername() != null ? incident.getAffectedUsername() : "system";
            assetDetails.put("type", "USER_ACCOUNT");
            assetDetails.put("username", uname);
            Optional<User> userOpt = userRepository.findByUsername(uname);
            if (userOpt.isPresent()) {
                User u = userOpt.get();
                assetDetails.put("role", u.getRole());
                assetDetails.put("accountStatus", (u.getLockedUntil() != null && u.getLockedUntil().isAfter(LocalDateTime.now())) ? "LOCKED" : "ACTIVE");
                assetDetails.put("failedLogins", u.getFailedLoginAttempts());
            }
            RiskResult riskResult = riskEngineService.calculateUserRisk(uname);
            riskBreakdown = riskResult.breakdown;
            recommendation = generateUserAccountRecommendation(uname, incident.getRiskScore());
        }

        report.put("affectedAsset", assetDetails);
        report.put("riskBreakdown", riskBreakdown);
        report.put("aiRecommendation", recommendation);

        // Lateral traversal path
        List<String> attackNodes = new ArrayList<>();
        if (incident.getAttackPath() != null && !incident.getAttackPath().isBlank()) {
            attackNodes = Arrays.asList(incident.getAttackPath().split(" → "));
        }
        report.put("attackPathNodes", attackNodes);

        // Compliance & Governance attestations
        List<String> complianceAttestations = List.of(
                "NIST SP 800-207: Zero Trust microsegmentation validation required for DMZ and core services.",
                "NIST CSF 2.0 (DE.CM-01): Network monitoring logs captured and retained in immutable audit ledger.",
                "ISO/IEC 27001 Control A.12.6.1: Management of technical vulnerabilities within prescribed 90-day SLA.",
                "NEDI Cyber Security Directive 2026-04: Digital service availability and integrity verification."
        );
        report.put("complianceAttestations", complianceAttestations);

        return report;
    }

    /**
     * Generate dynamic, professional HTML document for print/PDF and executive review.
     */
    public String generateIncidentReportHtml(Long incidentId) {
        Map<String, Object> data = generateIncidentReportJson(incidentId);

        @SuppressWarnings("unchecked")
        Map<String, Object> inc = (Map<String, Object>) data.get("incident");
        @SuppressWarnings("unchecked")
        Map<String, Object> asset = (Map<String, Object>) data.get("affectedAsset");
        @SuppressWarnings("unchecked")
        Map<String, Integer> breakdown = (Map<String, Integer>) data.get("riskBreakdown");
        AIRecommendation aiRec = (AIRecommendation) data.get("aiRecommendation");
        @SuppressWarnings("unchecked")
        List<String> pathNodes = (List<String>) data.get("attackPathNodes");
        @SuppressWarnings("unchecked")
        List<String> attestations = (List<String>) data.get("complianceAttestations");

        String reportId = (String) data.get("reportId");
        String generatedAt = (String) data.get("generatedAt");
        String title = (String) inc.get("title");
        String severity = String.valueOf(inc.get("severity"));
        String status = String.valueOf(inc.get("status"));
        int score = (int) inc.get("riskScore");

        String sevBadgeColor = switch (severity) {
            case "CRITICAL" -> "#ff3366";
            case "HIGH" -> "#ff8c00";
            case "MEDIUM" -> "#00c8ff";
            default -> "#00ff88";
        };

        String statusBadgeColor = switch (status) {
            case "RESOLVED" -> "#00ff88";
            case "CONTAINED" -> "#ffaa00";
            case "INVESTIGATING" -> "#00c8ff";
            default -> "#ff3366";
        };

        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n");
        sb.append("<meta charset=\"UTF-8\">\n");
        sb.append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
        sb.append("<title>").append(reportId).append(" - Incident Forensic Report</title>\n");
        sb.append("<style>\n");
        sb.append("  :root {\n");
        sb.append("    --bg: #0b0f19;\n");
        sb.append("    --card: #111827;\n");
        sb.append("    --border: #1f293d;\n");
        sb.append("    --text-primary: #f0f4f8;\n");
        sb.append("    --text-muted: #8a99ad;\n");
        sb.append("    --accent-blue: #00c8ff;\n");
        sb.append("    --accent-green: #00ff88;\n");
        sb.append("    --accent-red: #ff3366;\n");
        sb.append("    --accent-orange: #ff8c00;\n");
        sb.append("  }\n");
        sb.append("  * { box-sizing: border-box; margin: 0; padding: 0; }\n");
        sb.append("  body {\n");
        sb.append("    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;\n");
        sb.append("    background: var(--bg);\n");
        sb.append("    color: var(--text-primary);\n");
        sb.append("    line-height: 1.6;\n");
        sb.append("    padding: 32px 20px;\n");
        sb.append("  }\n");
        sb.append("  .container { max-width: 960px; margin: 0 auto; background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 36px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }\n");
        sb.append("  .header { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid var(--border); padding-bottom: 24px; margin-bottom: 28px; }\n");
        sb.append("  .logo-title h1 { font-size: 20px; font-weight: 800; letter-spacing: 1px; color: #fff; text-transform: uppercase; }\n");
        sb.append("  .logo-title p { font-size: 12px; color: var(--accent-blue); letter-spacing: 0.5px; font-weight: 600; margin-top: 4px; }\n");
        sb.append("  .report-meta { text-align: right; font-size: 12px; color: var(--text-muted); font-family: monospace; }\n");
        sb.append("  .badge { display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }\n");
        sb.append("  .section { margin-bottom: 28px; }\n");
        sb.append("  .section-title { font-size: 14px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: var(--accent-blue); margin-bottom: 12px; display: flex; align-items: center; gap: 8px; border-bottom: 1px solid var(--border); padding-bottom: 6px; }\n");
        sb.append("  .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }\n");
        sb.append("  .info-box { background: rgba(255,255,255,0.02); border: 1px solid var(--border); border-radius: 8px; padding: 14px 18px; }\n");
        sb.append("  .info-label { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }\n");
        sb.append("  .info-val { font-size: 14px; font-weight: 600; margin-top: 4px; }\n");
        sb.append("  .path-flow { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 12px 0; }\n");
        sb.append("  .path-pill { background: rgba(0,200,255,0.1); border: 1px solid var(--accent-blue); color: var(--accent-blue); padding: 6px 12px; border-radius: 20px; font-size: 12px; font-family: monospace; font-weight: 600; }\n");
        sb.append("  .path-arrow { color: var(--text-muted); font-weight: 700; }\n");
        sb.append("  table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }\n");
        sb.append("  th { text-align: left; padding: 10px; background: rgba(255,255,255,0.03); color: var(--text-muted); font-size: 11px; text-transform: uppercase; border-bottom: 1px solid var(--border); }\n");
        sb.append("  td { padding: 10px; border-bottom: 1px solid var(--border); }\n");
        sb.append("  .btn-print { background: var(--accent-blue); color: #000; border: none; padding: 10px 20px; border-radius: 6px; font-weight: 700; cursor: pointer; float: right; margin-bottom: 16px; }\n");
        sb.append("  .btn-print:hover { opacity: 0.9; }\n");
        sb.append("  @media print {\n");
        sb.append("    body { background: #fff; color: #000; padding: 0; }\n");
        sb.append("    .container { border: none; box-shadow: none; max-width: 100%; padding: 0; }\n");
        sb.append("    .btn-print { display: none; }\n");
        sb.append("    .info-box { background: #f9f9f9; border-color: #ddd; color: #000; }\n");
        sb.append("    .section-title { color: #0056b3; border-color: #ccc; }\n");
        sb.append("    th { background: #eee; color: #333; border-color: #ccc; }\n");
        sb.append("    td { border-color: #eee; color: #111; }\n");
        sb.append("    .path-pill { background: #eef6fc; border-color: #99c2ec; color: #0056b3; }\n");
        sb.append("  }\n");
        sb.append("</style>\n</head>\n<body>\n");

        sb.append("<div class=\"container\">\n");
        sb.append("  <button class=\"btn-print\" onclick=\"window.print()\">🖨️ Print / Save as PDF</button>\n");
        sb.append("  <div style=\"clear:both;\"></div>\n");

        // Header
        sb.append("  <div class=\"header\">\n");
        sb.append("    <div class=\"logo-title\">\n");
        sb.append("      <h1>CYBERSHIELD NEXUS // INCIDENT REPORT</h1>\n");
        sb.append("      <p>National Education Digital Infrastructure (NEDI) · SOC Command Center</p>\n");
        sb.append("    </div>\n");
        sb.append("    <div class=\"report-meta\">\n");
        sb.append("      <div>REF: <strong>").append(reportId).append("</strong></div>\n");
        sb.append("      <div>GENERATED: ").append(generatedAt).append("</div>\n");
        sb.append("      <div style=\"color:").append(sevBadgeColor).append(";font-weight:700;\">SIMULATION ENVIRONMENT</div>\n");
        sb.append("    </div>\n");
        sb.append("  </div>\n");

        // Executive Summary
        sb.append("  <div class=\"section\">\n");
        sb.append("    <div class=\"section-title\">1. Executive Incident Summary</div>\n");
        sb.append("    <div class=\"grid-2\">\n");
        sb.append("      <div class=\"info-box\">\n");
        sb.append("        <div class=\"info-label\">Incident Title</div>\n");
        sb.append("        <div class=\"info-val\">").append(escapeHtml(title)).append("</div>\n");
        sb.append("        <div style=\"margin-top:10px;display:flex;gap:8px;\">\n");
        sb.append("          <span class=\"badge\" style=\"background:").append(sevBadgeColor).append("22;color:").append(sevBadgeColor).append(";border:1px solid ").append(sevBadgeColor).append(";\">").append(severity).append("</span>\n");
        sb.append("          <span class=\"badge\" style=\"background:").append(statusBadgeColor).append("22;color:").append(statusBadgeColor).append(";border:1px solid ").append(statusBadgeColor).append(";\">").append(status).append("</span>\n");
        sb.append("        </div>\n");
        sb.append("      </div>\n");

        sb.append("      <div class=\"info-box\">\n");
        sb.append("        <div class=\"info-label\">Dynamic Risk Score</div>\n");
        sb.append("        <div class=\"info-val\" style=\"font-size:24px;font-family:monospace;color:").append(sevBadgeColor).append(";\">")
                .append(score).append(" / 100</div>\n");
        sb.append("        <div style=\"font-size:12px;color:var(--text-muted);\">Threat Actor Source IP: <strong>")
                .append(inc.get("sourceIp")).append("</strong></div>\n");
        sb.append("      </div>\n");
        sb.append("    </div>\n");

        sb.append("    <div class=\"info-box\" style=\"margin-top:12px;\">\n");
        sb.append("      <div class=\"info-label\">Description & Threat Impact</div>\n");
        sb.append("      <div style=\"margin-top:4px;font-size:13px;\">").append(escapeHtml((String) inc.get("description"))).append("</div>\n");
        sb.append("    </div>\n");
        sb.append("  </div>\n");

        // Affected Asset / User
        sb.append("  <div class=\"section\">\n");
        sb.append("    <div class=\"section-title\">2. Affected Asset Profile & Target Context</div>\n");
        sb.append("    <div class=\"grid-2\">\n");
        sb.append("      <div class=\"info-box\">\n");
        sb.append("        <div class=\"info-label\">Asset / Target Name</div>\n");
        sb.append("        <div class=\"info-val\">").append(asset.containsKey("name") ? asset.get("name") : ("User Account: " + asset.get("username"))).append("</div>\n");
        sb.append("        <div style=\"font-size:12px;color:var(--text-muted);margin-top:4px;\">Type: ").append(asset.get("type")).append(" | Service: ").append(asset.getOrDefault("serviceCode", "IDENTITY-AUTH")).append("</div>\n");
        sb.append("      </div>\n");

        sb.append("      <div class=\"info-box\">\n");
        sb.append("        <div class=\"info-label\">Operating Environment</div>\n");
        sb.append("        <div class=\"info-val\">").append(asset.getOrDefault("operatingSystem", "Multi-Tenant SSO Portal")).append("</div>\n");
        sb.append("        <div style=\"font-size:12px;color:var(--text-muted);margin-top:4px;\">Assigned Owner: ").append(asset.getOrDefault("owner", "Security Operations")).append("</div>\n");
        sb.append("      </div>\n");
        sb.append("    </div>\n");
        sb.append("  </div>\n");

        // Risk Factor Breakdown
        sb.append("  <div class=\"section\">\n");
        sb.append("    <div class=\"section-title\">3. Multi-Factor Risk Assessment Breakdown</div>\n");
        sb.append("    <table>\n");
        sb.append("      <thead><tr><th>Risk Factor Key</th><th>Description</th><th>Risk Contribution</th></tr></thead>\n");
        sb.append("      <tbody>\n");
        if (breakdown.isEmpty()) {
            sb.append("        <tr><td colspan=\"3\" style=\"text-align:center;color:var(--text-muted);\">Baseline posture — no active weighted penalty triggers.</td></tr>\n");
        } else {
            for (Map.Entry<String, Integer> entry : breakdown.entrySet()) {
                sb.append("        <tr>\n");
                sb.append("          <td style=\"font-family:monospace;font-weight:600;color:var(--accent-blue);\">").append(entry.getKey()).append("</td>\n");
                sb.append("          <td>").append(describeFactor(entry.getKey())).append("</td>\n");
                sb.append("          <td style=\"font-family:monospace;font-weight:700;color:var(--accent-red);\">+").append(entry.getValue()).append(" pts</td>\n");
                sb.append("        </tr>\n");
            }
        }
        sb.append("      </tbody>\n");
        sb.append("    </table>\n");
        sb.append("  </div>\n");

        // Lateral BFS Attack Path
        sb.append("  <div class=\"section\">\n");
        sb.append("    <div class=\"section-title\">4. Lateral Attack Traversal Analysis (BFS Shortest Path)</div>\n");
        if (pathNodes.isEmpty()) {
            sb.append("    <p style=\"font-size:12px;color:var(--text-muted);\">No lateral traversal recorded; isolated incident.</p>\n");
        } else {
            sb.append("    <div class=\"path-flow\">\n");
            for (int i = 0; i < pathNodes.size(); i++) {
                sb.append("      <span class=\"path-pill\">").append(escapeHtml(pathNodes.get(i))).append("</span>\n");
                if (i < pathNodes.size() - 1) {
                    sb.append("      <span class=\"path-arrow\">➔</span>\n");
                }
            }
            sb.append("    </div>\n");
            sb.append("    <p style=\"font-size:12px;color:var(--text-muted);margin-top:6px;\">Identified ").append(pathNodes.size() - 1)
                    .append(" intermediate lateral hops from initial foothold to target asset.</p>\n");
        }
        sb.append("  </div>\n");

        // Explainable AI & NIST CSF 2.0 Recommendations
        sb.append("  <div class=\"section\">\n");
        sb.append("    <div class=\"section-title\">5. Explainable AI Remediation & MITRE ATT&CK Mapping</div>\n");
        if (aiRec != null) {
            sb.append("    <div style=\"margin-bottom:14px;\">\n");
            sb.append("      <strong style=\"font-size:12px;color:var(--text-muted);text-transform:uppercase;\">Grounded MITRE ATT&CK Matrix:</strong>\n");
            sb.append("      <table>\n");
            sb.append("        <thead><tr><th>Technique ID</th><th>Technique Name</th><th>Tactic</th><th>Objective</th></tr></thead>\n");
            sb.append("        <tbody>\n");
            for (MitreAttackMapping m : aiRec.getMitreAttackMappings()) {
                sb.append("          <tr>\n");
                sb.append("            <td style=\"font-family:monospace;font-weight:700;color:var(--accent-orange);\">").append(m.getTechniqueId()).append("</td>\n");
                sb.append("            <td style=\"font-weight:600;\">").append(escapeHtml(m.getTechniqueName())).append("</td>\n");
                sb.append("            <td>").append(escapeHtml(m.getTactic())).append("</td>\n");
                sb.append("            <td style=\"font-size:12px;\">").append(escapeHtml(m.getDescription())).append("</td>\n");
                sb.append("          </tr>\n");
            }
            sb.append("        </tbody>\n");
            sb.append("      </table>\n");
            sb.append("    </div>\n");

            sb.append("    <div>\n");
            sb.append("      <strong style=\"font-size:12px;color:var(--text-muted);text-transform:uppercase;\">Prioritized Prescriptive Actions:</strong>\n");
            sb.append("      <table>\n");
            sb.append("        <thead><tr><th>Priority</th><th>Action Item</th><th>Owner Team</th><th>Estimated Impact</th></tr></thead>\n");
            sb.append("        <tbody>\n");
            for (RemediationAction act : aiRec.getPrioritizedActions()) {
                sb.append("          <tr>\n");
                sb.append("            <td><span class=\"badge\" style=\"background:rgba(255,51,102,0.15);color:var(--accent-red);\">").append(act.getPriority()).append("</span></td>\n");
                sb.append("            <td style=\"font-weight:600;\">").append(escapeHtml(act.getAction())).append("</td>\n");
                sb.append("            <td style=\"font-size:12px;\">").append(escapeHtml(act.getOwnerTeam())).append("</td>\n");
                sb.append("            <td style=\"font-family:monospace;color:var(--accent-green);font-weight:700;\">").append(act.getEstimatedImpact()).append("</td>\n");
                sb.append("          </tr>\n");
            }
            sb.append("        </tbody>\n");
            sb.append("      </table>\n");
            sb.append("    </div>\n");
        }
        sb.append("  </div>\n");

        // Incident Response Lifecycle & Sign-off
        sb.append("  <div class=\"section\">\n");
        sb.append("    <div class=\"section-title\">6. Containment Audit Trail & Forensic Notes</div>\n");
        sb.append("    <div class=\"info-box\">\n");
        sb.append("      <div class=\"info-label\">Analyst Remediation Log</div>\n");
        sb.append("      <div style=\"font-size:13px;margin-top:6px;font-family:monospace;white-space:pre-wrap;\">")
                .append(inc.get("remediationNotes") != null ? escapeHtml((String) inc.get("remediationNotes")) : "No manual notes logged.")
                .append("</div>\n");
        sb.append("    </div>\n");

        sb.append("    <div class=\"grid-2\" style=\"margin-top:12px;\">\n");
        sb.append("      <div class=\"info-box\">\n");
        sb.append("        <div class=\"info-label\">Containment Verification</div>\n");
        sb.append("        <div class=\"info-val\">").append(inc.get("containedBy") != null ? ("Contained by " + inc.get("containedBy") + " at " + inc.get("containedAt")) : "Status: Not yet contained").append("</div>\n");
        sb.append("      </div>\n");
        sb.append("      <div class=\"info-box\">\n");
        sb.append("        <div class=\"info-label\">Resolution Sign-Off</div>\n");
        sb.append("        <div class=\"info-val\">").append(inc.get("resolvedBy") != null ? ("Resolved by " + inc.get("resolvedBy") + " at " + inc.get("resolvedAt")) : "Status: Pending full resolution").append("</div>\n");
        sb.append("      </div>\n");
        sb.append("    </div>\n");
        sb.append("  </div>\n");

        // Compliance Footer
        sb.append("  <div class=\"section\" style=\"border-top:1px solid var(--border);padding-top:18px;\">\n");
        sb.append("    <div class=\"info-label\">Governance & Regulatory Declarations</div>\n");
        sb.append("    <ul style=\"font-size:11px;color:var(--text-muted);margin-left:20px;margin-top:6px;\">\n");
        for (String att : attestations) {
            sb.append("      <li>").append(escapeHtml(att)).append("</li>\n");
        }
        sb.append("    </ul>\n");
        sb.append("  </div>\n");

        sb.append("</div>\n</body>\n</html>\n");
        return sb.toString();
    }

    private AIRecommendation generateUserAccountRecommendation(String username, int riskScore) {
        return AIRecommendation.builder()
                .assetId(0L)
                .assetName("Account: " + username)
                .riskScore(riskScore)
                .severity(riskScore >= 85 ? "HIGH" : "MEDIUM")
                .executiveSummary("Credential stuffing / brute-force password guessing targeting username '" + username + "'.")
                .primaryThreatFactors(List.of("Repeated failed authentications exceeding security threshold within short window."))
                .mitreAttackMappings(List.of(
                        MitreAttackMapping.builder()
                                .techniqueId("T1110.001")
                                .techniqueName("Password Guessing")
                                .tactic("Credential Access")
                                .description("Adversary systematically submits candidate passwords to breach authentication barriers.")
                                .build(),
                        MitreAttackMapping.builder()
                                .techniqueId("T1078")
                                .techniqueName("Valid Accounts")
                                .tactic("Defense Evasion / Persistence")
                                .description("Obtaining valid credentials allows attackers to operate within standard audit thresholds.")
                                .build()
                ))
                .nistCsfFunctions(List.of(
                        "NIST CSF PR.AC-07 (Access Control & Credential Protection)",
                        "NIST CSF DE.CM-01 (Continuous Security & Audit Monitoring)"
                ))
                .prioritizedActions(List.of(
                        RemediationAction.builder()
                                .priority("IMMEDIATE")
                                .action("Temporarily lock user account '" + username + "' and invalidate active session tokens.")
                                .ownerTeam("Identity & Access Management (IAM)")
                                .estimatedImpact("-40 Risk Points")
                                .build(),
                        RemediationAction.builder()
                                .priority("SECONDARY")
                                .action("Force mandatory FIDO2 / hardware MFA setup upon password reset.")
                                .ownerTeam("User Security Operations")
                                .estimatedImpact("-20 Risk Points")
                                .build()
                ))
                .projectedScorePostRemediation(Math.max(0, riskScore - 60))
                .confidenceScore("94% (Deterministic Rule Correlation)")
                .build();
    }

    private String describeFactor(String factorKey) {
        if (factorKey.equals("unpatched_server")) return "Host OS and runtime missing security updates for over 90 days.";
        if (factorKey.equals("expired_license")) return "Assigned software/database license expired, blocking critical vendor hotfixes.";
        if (factorKey.startsWith("owner_account_attacked")) return "Asset administrator account experiencing active brute-force login attempts.";
        if (factorKey.equals("low_trust_reachable")) return "Node is directly accessible from an untrusted or DMZ edge network path.";
        if (factorKey.equals("failed_logins_recent")) return "Burst of repeated failed authentication attempts detected within 5 minutes.";
        return "Heuristic anomaly score factor triggered by risk engine.";
    }

    // ─────────────────────────────────────────────────────────────────────
    // ENHANCEMENT (Part 1, #7): PDF Incident Report Export
    // ─────────────────────────────────────────────────────────────────────

    /**
     * Renders the incident report as a downloadable PDF (byte array).
     * Uses a simplified, table-based HTML layout (no flexbox/grid/CSS
     * variables) because the pure-Java openhtmltopdf renderer only
     * supports a CSS 2.1-level subset — the flashy dashboard-style HTML
     * from generateIncidentReportHtml() is for the browser/print-preview,
     * this one is purpose-built for reliable PDF output.
     */
    @SuppressWarnings("unchecked")
    public byte[] generateIncidentReportPdf(Long incidentId) {
        Map<String, Object> data = generateIncidentReportJson(incidentId);
        Map<String, Object> inc = (Map<String, Object>) data.get("incident");
        Map<String, Object> asset = (Map<String, Object>) data.get("affectedAsset");
        Map<String, Integer> breakdown = (Map<String, Integer>) data.get("riskBreakdown");
        List<String> attestations = (List<String>) data.get("complianceAttestations");

        String html = buildPdfSafeHtml(
                (String) data.get("reportId"),
                (String) data.get("generatedAt"),
                inc, asset, breakdown, attestations);

        try {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            PdfRendererBuilder builder = new PdfRendererBuilder();
            builder.useFastMode();
            builder.withHtmlContent(html, null);
            builder.toStream(os);
            builder.run();
            return os.toByteArray();
        } catch (Exception e) {
            log.error("PDF generation failed for incident #{}: {}", incidentId, e.getMessage());
            throw new RuntimeException("Could not generate PDF report: " + e.getMessage(), e);
        }
    }

    private String buildPdfSafeHtml(String reportId, String generatedAt,
                                     Map<String, Object> inc, Map<String, Object> asset,
                                     Map<String, Integer> breakdown, List<String> attestations) {
        StringBuilder sb = new StringBuilder();
        sb.append("<html><head><meta charset=\"UTF-8\"/><style>")
          .append("body{font-family:Helvetica,Arial,sans-serif;font-size:11px;color:#111;}")
          .append("h1{font-size:18px;margin-bottom:2px;}")
          .append("h2{font-size:13px;color:#0056b3;border-bottom:1px solid #ccc;padding-bottom:4px;margin-top:20px;}")
          .append(".meta{color:#666;font-size:10px;margin-bottom:16px;}")
          .append("table{width:100%;border-collapse:collapse;margin-top:6px;}")
          .append("td,th{border:1px solid #ddd;padding:6px 8px;text-align:left;font-size:11px;}")
          .append("th{background:#f2f2f2;}")
          .append(".badge{padding:2px 8px;border-radius:4px;font-weight:bold;color:#fff;}")
          .append("</style></head><body>");

        sb.append("<h1>CyberShield Nexus — Incident Forensic Report</h1>");
        sb.append("<div class=\"meta\">Report ID: ").append(escapeHtml(reportId))
          .append(" &nbsp;|&nbsp; Generated: ").append(escapeHtml(generatedAt))
          .append(" &nbsp;|&nbsp; Classification: OFFICIAL USE ONLY // NEDI ACADEMIC SOC SIMULATION</div>");

        String severity = String.valueOf(inc.get("severity"));
        String badgeColor = switch (severity) {
            case "CRITICAL" -> "#c0392b";
            case "HIGH" -> "#e67e22";
            case "MEDIUM" -> "#2980b9";
            default -> "#27ae60";
        };

        sb.append("<h2>Incident Summary</h2><table>");
        sb.append("<tr><th>Title</th><td>").append(escapeHtml((String) inc.get("title"))).append("</td></tr>");
        sb.append("<tr><th>Severity</th><td><span class=\"badge\" style=\"background:")
          .append(badgeColor).append("\">").append(escapeHtml(severity)).append("</span></td></tr>");
        sb.append("<tr><th>Status</th><td>").append(escapeHtml(String.valueOf(inc.get("status")))).append("</td></tr>");
        sb.append("<tr><th>Risk Score</th><td>").append(inc.get("riskScore")).append("/100</td></tr>");
        sb.append("<tr><th>Source IP</th><td>").append(escapeHtml((String) inc.get("sourceIp"))).append("</td></tr>");
        sb.append("<tr><th>Created At</th><td>").append(escapeHtml((String) inc.get("createdAt"))).append("</td></tr>");
        sb.append("<tr><th>Description</th><td>").append(escapeHtml((String) inc.get("description"))).append("</td></tr>");
        sb.append("</table>");

        sb.append("<h2>Affected Asset</h2><table>");
        for (Map.Entry<String, Object> e : asset.entrySet()) {
            sb.append("<tr><th>").append(escapeHtml(e.getKey())).append("</th><td>")
              .append(escapeHtml(String.valueOf(e.getValue()))).append("</td></tr>");
        }
        sb.append("</table>");

        sb.append("<h2>Risk Score Breakdown</h2><table><tr><th>Factor</th><th>Points</th><th>Description</th></tr>");
        for (Map.Entry<String, Integer> e : breakdown.entrySet()) {
            sb.append("<tr><td>").append(escapeHtml(e.getKey())).append("</td><td>+")
              .append(e.getValue()).append("</td><td>").append(escapeHtml(describeFactor(e.getKey())))
              .append("</td></tr>");
        }
        sb.append("</table>");

        sb.append("<h2>Compliance & Governance Attestations</h2><table>");
        for (String att : attestations) {
            sb.append("<tr><td>").append(escapeHtml(att)).append("</td></tr>");
        }
        sb.append("</table>");

        sb.append("</body></html>");
        return sb.toString();
    }

    private String escapeHtml(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}
