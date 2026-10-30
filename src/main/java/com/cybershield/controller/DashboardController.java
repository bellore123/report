package com.cybershield.controller;

import com.cybershield.model.AuditLog;
import com.cybershield.model.DigitalService;
import com.cybershield.model.DigitalService.ServiceStatus;
import com.cybershield.model.Institution.InstitutionStatus;
import com.cybershield.model.License;
import com.cybershield.service.*;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/dashboard")
@RequiredArgsConstructor
public class DashboardController {

    private final ServerService         serverService;
    private final FirewallService       firewallService;
    private final LicenseService        licenseService;
    private final HardwareService       hardwareService;
    private final AuditLogService       auditLogService;
    private final IncidentService       incidentService;
    private final RiskEngineService     riskEngineService;
    private final DigitalServiceService digitalServiceService;
    private final InstitutionService    institutionService;

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN','SERVER_ADMIN','VIEWER')")
    public ResponseEntity<Map<String, Object>> getDashboard() {

        Map<String, Object> dashboard = new HashMap<>();

        // ── Asset Counts ──────────────────────────────────────────
        Map<String, Object> counts = new HashMap<>();
        counts.put("totalServers",     serverService.countTotal());
        counts.put("runningServers",   serverService.countRunning());
        counts.put("totalFirewalls",   firewallService.countTotal());
        counts.put("activeFirewalls",  firewallService.countActive());
        counts.put("totalLicenses",    licenseService.countTotal());
        counts.put("expiredLicenses",  licenseService.countExpired());
        counts.put("totalHardware",    hardwareService.countTotal());
        counts.put("openIncidents",    incidentService.countOpenIncidents());
        counts.put("totalServices",    digitalServiceService.countTotal());
        counts.put("healthyServices",  digitalServiceService.countByStatus(ServiceStatus.HEALTHY));
        counts.put("degradedServices", digitalServiceService.countByStatus(ServiceStatus.DEGRADED));
        counts.put("highRiskServices", digitalServiceService.countByStatus(ServiceStatus.HIGH_RISK)
                                     + digitalServiceService.countByStatus(ServiceStatus.DOWN));
        counts.put("criticalServices", digitalServiceService.countCriticalServices());
        counts.put("totalInstitutions", institutionService.countTotal());
        counts.put("activeInstitutions", institutionService.countByStatus(InstitutionStatus.ACTIVE));
        counts.put("atRiskInstitutions", institutionService.countByStatus(InstitutionStatus.DEGRADED)
                + institutionService.countByStatus(InstitutionStatus.HIGH_RISK)
                + institutionService.countByStatus(InstitutionStatus.OFFLINE));
        counts.put("representedInstitutionCoverage", 500);
        dashboard.put("counts", counts);

        // ── NEDI Service Health List ──────────────────────────────
        List<DigitalService> allServices = digitalServiceService.getAllServices();
        dashboard.put("services", allServices);
        dashboard.put("institutions", institutionService.getAll());
        dashboard.put("atRiskInstitutions", institutionService.getAtRiskInstitutions());

        // ── Exam Portal Spotlight ─────────────────────────────────
        allServices.stream()
                .filter(s -> "EXAM_PORTAL".equals(s.getServiceCode()))
                .findFirst()
                .ifPresent(exam -> {
                    Map<String, Object> alert = new HashMap<>();
                    alert.put("name",        exam.getName() != null ? exam.getName() : "Exam Portal");
                    alert.put("status",      exam.getStatus() != null ? exam.getStatus().name() : "HIGH_RISK");
                    alert.put("domain",      exam.getHostDomain() != null ? exam.getHostDomain() : "exam.nedi.local");
                    alert.put("criticality", exam.getCriticalityLevel());
                    alert.put("message",     "Unpatched app server + expired Oracle license detected");
                    dashboard.put("examPortalAlert", alert);
                });

        dashboard.put("highRiskServices", digitalServiceService.getHighRiskServices());

        // ── License Alerts ────────────────────────────────────────
        List<License> expired      = licenseService.getExpiredLicenses();
        List<License> expiringSoon = licenseService.getExpiringSoon();
        dashboard.put("expiredLicenses",      expired);
        dashboard.put("expiringSoonLicenses", expiringSoon);

        // ── Unpatched Servers ─────────────────────────────────────
        var unpatchedServers = serverService.getUnpatchedServers();
        dashboard.put("unpatchedServers", unpatchedServers);

        // ── Risk Summary ──────────────────────────────────────────
        var allRisks = riskEngineService.calculateAllServerRisks();
        long highRiskCount = allRisks.values().stream().filter(r -> r.score >= 70).count();
        dashboard.put("highRiskServerCount", highRiskCount);

        long total = serverService.countTotal();
        int complianceScore = total > 0 ? (int) ((total - highRiskCount) * 100 / total) : 100;
        dashboard.put("complianceScore", complianceScore);

        // ── Open Incidents ────────────────────────────────────────
        dashboard.put("openIncidents", incidentService.getOpenIncidents());

        // ── Recent Audit Log ──────────────────────────────────────
        dashboard.put("recentAuditLogs", auditLogService.getRecentLogs());

        // ── Total Alerts ──────────────────────────────────────────
        int totalAlerts = expired.size() + expiringSoon.size()
                + unpatchedServers.size() + (int) incidentService.countOpenIncidents();
        dashboard.put("totalAlerts", totalAlerts);

        return ResponseEntity.ok(dashboard);
    }
}
