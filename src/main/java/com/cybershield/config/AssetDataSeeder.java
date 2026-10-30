package com.cybershield.config;

import com.cybershield.model.*;
import com.cybershield.model.AssetRelationship.AssetType;
import com.cybershield.model.AssetRelationship.RelationshipType;
import com.cybershield.model.DigitalService.ServiceStatus;
import com.cybershield.model.DigitalService.ServiceType;
import com.cybershield.model.Institution.InstitutionStatus;
import com.cybershield.model.Institution.InstitutionType;
import com.cybershield.model.Server.ServerStatus;
import com.cybershield.model.Firewall.FirewallStatus;
import com.cybershield.model.License.LicenseStatus;
import com.cybershield.model.License.LicenseType;
import com.cybershield.model.Hardware.HardwareStatus;
import com.cybershield.model.Hardware.HardwareType;
import com.cybershield.model.LoadBalancer.Algorithm;
import com.cybershield.model.LoadBalancer.LbStatus;
import com.cybershield.model.Incident.IncidentStatus;
import com.cybershield.model.Incident.Severity;
import com.cybershield.model.AuditLog.Action;
import com.cybershield.repository.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

/**
 * AssetDataSeeder — seeds all NEDI infrastructure assets.
 *
 * NEDI Demo Story:
 *   The 'viewer' account (low-privilege student portal user) is compromised.
 *   Attacker pivots: viewer → NEDI-DMZ-FW-01 → NEDI-EXAM-WEB-01
 *                            → NEDI-EXAM-APP-01 → NEDI-EXAM-DB-01
 *
 *   NEDI-EXAM-APP-01 is intentionally UNPATCHED (120 days).
 *   NEDI-EXAM-DB-01 has an EXPIRED Oracle license → risk score 55+.
 *   This is what BFS finds and Risk Engine flags.
 *
 * Runs AFTER DataInitializer (Order 2).
 */
@Component
@Order(2)
@RequiredArgsConstructor
@Slf4j
public class AssetDataSeeder implements CommandLineRunner {

    private final ServerRepository              serverRepository;
    private final FirewallRepository            firewallRepository;
    private final FirewallRuleRepository        firewallRuleRepository;
    private final LicenseRepository             licenseRepository;
    private final HardwareRepository            hardwareRepository;
    private final AssetRelationshipRepository   relationshipRepository;
    private final DigitalServiceRepository      digitalServiceRepository;
    private final InstitutionRepository         institutionRepository;
    private final LoadBalancerRepository        loadBalancerRepository;
    private final LoadBalancerBackendRepository loadBalancerBackendRepository;
    private final IncidentRepository            incidentRepository;
    private final AuditLogRepository            auditLogRepository;

    @Override
    public void run(String... args) {
        // Detect old pre-Phase2 generic names — wipe and re-seed with NEDI data
        boolean hasOldData = serverRepository.existsByNameContaining("Server-Web-01")
                || serverRepository.existsByNameContaining("Server-App-02")
                || serverRepository.existsByNameContaining("Server-DB-03");

        if (hasOldData) {
            log.warn("Old generic server data detected — wiping and re-seeding with NEDI data...");
            relationshipRepository.deleteAll();
            firewallRuleRepository.deleteAll();
            licenseRepository.deleteAll();
            hardwareRepository.deleteAll();
            firewallRepository.deleteAll();
            serverRepository.deleteAll();
            digitalServiceRepository.deleteAll();
            institutionRepository.deleteAll();
        }

        if (serverRepository.count() == 0) {
            seedServers();
            seedFirewalls();
            seedFirewallRules();
            seedLicenses();
            seedHardware();
            log.info("NEDI asset seed data loaded successfully");
        } else {
            log.debug("NEDI assets already seeded — skipping asset seed");
            if (firewallRuleRepository.count() == 0) {
                // Servers/firewalls already existed from a previous run that predates
                // the Firewall Rule module — backfill the rules without touching
                // the rest of the asset data.
                seedFirewallRules();
            }
        }

        if (digitalServiceRepository.count() == 0) {
            seedDigitalServices();
        } else {
            log.debug("Digital services already seeded — skipping");
        }

        if (institutionRepository.count() == 0) {
            seedInstitutions();
        } else {
            log.debug("Institutions already seeded — skipping");
        }

        if (loadBalancerRepository.count() < 3) {
            seedLoadBalancers();
        } else {
            log.debug("Load balancers already seeded — skipping");
        }

        if (incidentRepository.count() < 5) {
            seedIncidents();
        } else {
            log.debug("Incidents already seeded — skipping");
        }

        if (auditLogRepository.count() < 10) {
            seedAuditLogs();
        } else {
            log.debug("Audit logs already seeded — skipping");
        }

        seedGraph();
    }

    // ─────────────────────────────────────────────────────────────────
    // SERVERS — NEDI infrastructure naming convention
    // ─────────────────────────────────────────────────────────────────
    private void seedServers() {

        // NEDI Student Portal Web Server — recently patched (low risk)
        serverRepository.save(Server.builder()
                .name("NEDI-STUDENT-WEB-01").ipAddress("10.0.1.10")
                .operatingSystem("Ubuntu").osVersion("22.04 LTS")
                .status(ServerStatus.RUNNING).location("DMZ Rack A1")
                .owner("viewer")
                .serviceCode("STUDENT_PORTAL")
                .cpuCores(8).ramGb(32).storageGb(500)
                .lastPatchDate(LocalDate.now().minusDays(10))
                .warrantyExpiry(LocalDate.now().plusYears(2))
                .notes("Student Portal frontend — recently patched, low risk").build());

        // NEDI Exam Portal App Server — UNPATCHED 120 days (HIGH risk +30)
        serverRepository.save(Server.builder()
                .name("NEDI-EXAM-APP-01").ipAddress("10.0.1.11")
                .operatingSystem("CentOS").osVersion("7.9")
                .status(ServerStatus.RUNNING).location("Core Rack A2")
                .owner("serveradmin")
                .serviceCode("EXAM_PORTAL")
                .cpuCores(16).ramGb(64).storageGb(1000)
                .lastPatchDate(LocalDate.now().minusDays(120))
                .warrantyExpiry(LocalDate.now().plusYears(1))
                .notes("Exam Portal application server — UNPATCHED 120 DAYS — HIGH RISK").build());

        // NEDI Exam Portal DB Server — UNPATCHED + EXPIRED LICENSE (CRITICAL risk 55+)
        serverRepository.save(Server.builder()
                .name("NEDI-EXAM-DB-01").ipAddress("10.0.1.12")
                .operatingSystem("Windows Server").osVersion("2019")
                .status(ServerStatus.RUNNING).location("DB Rack A3")
                .owner("admin")
                .serviceCode("EXAM_PORTAL")
                .cpuCores(32).ramGb(128).storageGb(5000)
                .lastPatchDate(LocalDate.now().minusDays(95))
                .warrantyExpiry(LocalDate.now().plusMonths(3))
                .notes("Exam Portal database — HIGH VALUE TARGET — unpatched + expired license").build());

        // NEDI Faculty Portal Server — healthy
        serverRepository.save(Server.builder()
                .name("NEDI-FACULTY-WEB-01").ipAddress("10.0.1.13")
                .operatingSystem("Ubuntu").osVersion("22.04 LTS")
                .status(ServerStatus.RUNNING).location("Core Rack B1")
                .owner("serveradmin")
                .serviceCode("FACULTY_PORTAL")
                .cpuCores(8).ramGb(32).storageGb(500)
                .lastPatchDate(LocalDate.now().minusDays(30))
                .warrantyExpiry(LocalDate.now().plusYears(2))
                .notes("Faculty portal — healthy, recently patched").build());

        // NEDI ERP Server — in maintenance
        serverRepository.save(Server.builder()
                .name("NEDI-ERP-APP-01").ipAddress("10.0.1.14")
                .operatingSystem("Red Hat Enterprise Linux").osVersion("8.6")
                .status(ServerStatus.MAINTENANCE).location("Core Rack B2")
                .owner("serveradmin")
                .serviceCode("ERP")
                .cpuCores(16).ramGb(64).storageGb(2000)
                .lastPatchDate(LocalDate.now().minusDays(5))
                .warrantyExpiry(LocalDate.now().plusYears(3))
                .notes("ERP server — under scheduled maintenance").build());

        log.info("Seeded 5 NEDI servers (Exam Portal at HIGH RISK)");
    }

    // ─────────────────────────────────────────────────────────────────
    // FIREWALLS — NEDI naming convention
    // ─────────────────────────────────────────────────────────────────
    private void seedFirewalls() {

        // NEDI DMZ Edge Firewall — outdated firmware (attack entry point)
        firewallRepository.save(Firewall.builder()
                .name("NEDI-DMZ-FW-01").vendor("Cisco").model("ASA 5505")
                .ipAddress("10.0.0.1").firmwareVersion("9.8.4")
                .status(FirewallStatus.ACTIVE).location("DMZ Rack")
                .activeRulesCount(142)
                .lastRuleReviewDate(LocalDate.now().minusDays(45))
                .lastFirmwareUpdate(LocalDate.now().minusDays(200))
                .warrantyExpiry(LocalDate.now().plusYears(1))
                .notes("Primary DMZ edge firewall — OUTDATED FIRMWARE 200 days").build());

        // NEDI Core Internal Firewall — well maintained
        firewallRepository.save(Firewall.builder()
                .name("NEDI-CORE-FW-01").vendor("Palo Alto").model("PA-220")
                .ipAddress("10.0.1.1").firmwareVersion("10.2.3")
                .status(FirewallStatus.ACTIVE).location("Core Rack")
                .activeRulesCount(89)
                .lastRuleReviewDate(LocalDate.now().minusDays(15))
                .lastFirmwareUpdate(LocalDate.now().minusDays(20))
                .warrantyExpiry(LocalDate.now().plusYears(2))
                .notes("Core internal firewall — up to date").build());

        // NEDI DB Zone Firewall — protects exam database
        firewallRepository.save(Firewall.builder()
                .name("NEDI-DB-FW-01").vendor("Fortinet").model("FortiGate 60F")
                .ipAddress("10.0.1.50").firmwareVersion("7.2.1")
                .status(FirewallStatus.ACTIVE).location("DB Rack")
                .activeRulesCount(55)
                .lastRuleReviewDate(LocalDate.now().minusDays(7))
                .lastFirmwareUpdate(LocalDate.now().minusDays(30))
                .warrantyExpiry(LocalDate.now().plusYears(3))
                .notes("Database zone firewall — protects Exam DB").build());

        log.info("Seeded 3 NEDI firewalls (DMZ-FW-01 has outdated firmware)");
    }

    // ─────────────────────────────────────────────────────────────────
    // FIREWALL RULES — 5 rules per server (25 total), each attached to
    // whichever firewall actually fronts that server in the topology
    // (matches the FIREWALL → SERVER edges built in seedGraph()).
    // ─────────────────────────────────────────────────────────────────
    private void seedFirewallRules() {

        var servers   = serverRepository.findAll();
        var firewalls = firewallRepository.findAll();

        Server studentWeb = findServer(servers, "STUDENT-WEB");
        Server examApp    = findServer(servers, "EXAM-APP");
        Server examDb     = findServer(servers, "EXAM-DB");
        Server facultyWeb = findServer(servers, "FACULTY-WEB");
        Server erpApp     = findServer(servers, "ERP-APP");

        Firewall dmzFw  = findFirewall(firewalls, "DMZ-FW");
        Firewall coreFw = findFirewall(firewalls, "CORE-FW");
        Firewall dbFw   = findFirewall(firewalls, "DB-FW");

        // NEDI-STUDENT-WEB-01 — behind the DMZ edge firewall (internet-facing)
        seedRulesForServer(dmzFw, studentWeb, "STUDENT-WEB");

        // NEDI-EXAM-APP-01 — behind the core internal firewall
        seedRulesForServer(coreFw, examApp, "EXAM-APP");

        // NEDI-EXAM-DB-01 — behind the dedicated DB zone firewall
        seedRulesForServer(dbFw, examDb, "EXAM-DB");

        // NEDI-FACULTY-WEB-01 — behind the core internal firewall
        seedRulesForServer(coreFw, facultyWeb, "FACULTY-WEB");

        // NEDI-ERP-APP-01 — behind the DMZ edge firewall
        seedRulesForServer(dmzFw, erpApp, "ERP-APP");

        log.info("Seeded 25 firewall rules (5 per server across 5 NEDI servers)");
    }

    private Server findServer(java.util.List<Server> servers, String nameContains) {
        return servers.stream().filter(s -> s.getName().contains(nameContains)).findFirst().orElse(null);
    }

    private Firewall findFirewall(java.util.List<Firewall> firewalls, String nameContains) {
        return firewalls.stream().filter(f -> f.getName().contains(nameContains)).findFirst().orElse(null);
    }

    /** Standard 5-rule set applied to one server: HTTPS/SSH allowed, DB/RDP/telnet denied. */
    private void seedRulesForServer(Firewall firewall, Server server, String label) {
        if (firewall == null || server == null) {
            log.warn("Skipping firewall rule seed for {} — firewall or server not found", label);
            return;
        }
        String ip = server.getIpAddress();

        firewallRuleRepository.save(FirewallRule.builder()
                .firewall(firewall).name("Allow HTTPS inbound - " + label)
                .sourceIp("0.0.0.0/0").destinationIp(ip).port("443")
                .protocol(FirewallRule.Protocol.TCP).action(FirewallRule.RuleAction.ALLOW)
                .priority(100).enabled(true)
                .description("Allow public HTTPS traffic to " + server.getName()).build());

        firewallRuleRepository.save(FirewallRule.builder()
                .firewall(firewall).name("Allow SSH from admin subnet - " + label)
                .sourceIp("10.0.0.0/16").destinationIp(ip).port("22")
                .protocol(FirewallRule.Protocol.TCP).action(FirewallRule.RuleAction.ALLOW)
                .priority(110).enabled(true)
                .description("Allow management SSH access to " + server.getName() + " from internal admin subnet").build());

        firewallRuleRepository.save(FirewallRule.builder()
                .firewall(firewall).name("Allow ICMP ping - " + label)
                .sourceIp("10.0.0.0/16").destinationIp(ip).port("ANY")
                .protocol(FirewallRule.Protocol.ICMP).action(FirewallRule.RuleAction.ALLOW)
                .priority(120).enabled(true)
                .description("Allow internal health-check pings to " + server.getName()).build());

        firewallRuleRepository.save(FirewallRule.builder()
                .firewall(firewall).name("Deny Telnet - " + label)
                .sourceIp("0.0.0.0/0").destinationIp(ip).port("23")
                .protocol(FirewallRule.Protocol.TCP).action(FirewallRule.RuleAction.DENY)
                .priority(130).enabled(true)
                .description("Block legacy insecure Telnet access to " + server.getName()).build());

        firewallRuleRepository.save(FirewallRule.builder()
                .firewall(firewall).name("Deny direct RDP from internet - " + label)
                .sourceIp("0.0.0.0/0").destinationIp(ip).port("3389")
                .protocol(FirewallRule.Protocol.TCP).action(FirewallRule.RuleAction.DENY)
                .priority(140).enabled(true)
                .description("Block unauthenticated internet-facing RDP to " + server.getName()).build());
    }

    // ─────────────────────────────────────────────────────────────────
    // LICENSES — tied to NEDI services
    // ─────────────────────────────────────────────────────────────────
    private void seedLicenses() {

        // Fetch servers seeded above
        var servers = serverRepository.findAll();
        Server studentWeb = servers.stream().filter(s -> s.getName().contains("STUDENT-WEB")).findFirst().orElse(null);
        Server examApp    = servers.stream().filter(s -> s.getName().contains("EXAM-APP")).findFirst().orElse(null);
        Server examDb     = servers.stream().filter(s -> s.getName().contains("EXAM-DB")).findFirst().orElse(null);

        // EXPIRED — Oracle license on Exam DB server (triggers risk +25 on NEDI-EXAM-DB-01)
        licenseRepository.save(License.builder()
                .softwareName("Oracle Database 19c").vendor("Oracle")
                .licenseType(LicenseType.PER_SEAT).totalSeats(5).usedSeats(5)
                .expiryDate(LocalDate.now().minusDays(30))
                .purchaseDate(LocalDate.now().minusYears(3))
                .renewalCost(45000.00).assignedTo("NEDI-EXAM-DB-01")
                .server(examDb)
                .status(LicenseStatus.EXPIRED)
                .notes("CRITICAL: Expired Oracle license on Exam DB — compliance violation").build());

        // EXPIRING SOON — Windows license on Student Web server
        licenseRepository.save(License.builder()
                .softwareName("Windows Server 2022").vendor("Microsoft")
                .licenseType(LicenseType.PER_SEAT).totalSeats(10).usedSeats(7)
                .expiryDate(LocalDate.now().plusDays(15))
                .purchaseDate(LocalDate.now().minusYears(1))
                .renewalCost(12000.00).assignedTo("NEDI-STUDENT-WEB-01")
                .server(studentWeb)
                .status(LicenseStatus.PENDING_RENEWAL)
                .notes("Student Portal web license expiring in 15 days — renew immediately").build());

        // ACTIVE — CrowdStrike endpoint protection for all servers
        licenseRepository.save(License.builder()
                .softwareName("CrowdStrike Falcon EDR").vendor("CrowdStrike")
                .licenseType(LicenseType.SUBSCRIPTION).totalSeats(50).usedSeats(23)
                .expiryDate(LocalDate.now().plusYears(1))
                .purchaseDate(LocalDate.now().minusMonths(3))
                .renewalCost(8500.00).assignedTo("All NEDI Servers")
                .status(LicenseStatus.ACTIVE)
                .notes("Endpoint security for all NEDI infrastructure — active and healthy").build());

        // ACTIVE — RHEL for Exam App server
        licenseRepository.save(License.builder()
                .softwareName("Red Hat Enterprise Linux").vendor("Red Hat")
                .licenseType(LicenseType.SUBSCRIPTION).totalSeats(5).usedSeats(3)
                .expiryDate(LocalDate.now().plusMonths(8))
                .purchaseDate(LocalDate.now().minusMonths(4))
                .renewalCost(6000.00).assignedTo("NEDI-EXAM-APP-01")
                .server(examApp)
                .status(LicenseStatus.ACTIVE)
                .notes("RHEL subscription for Exam Portal app server").build());

        log.info("Seeded 4 licenses (Oracle EXPIRED on Exam DB = risk +25)");
    }

    // ─────────────────────────────────────────────────────────────────
    // HARDWARE — NEDI infrastructure asset tags
    // ─────────────────────────────────────────────────────────────────
    private void seedHardware() {

        hardwareRepository.save(Hardware.builder()
                .assetTag("NEDI-SW-001").name("Core Switch Layer-3")
                .hardwareType(HardwareType.SWITCH).manufacturer("Cisco")
                .model("Catalyst 3750").serialNumber("CAT3750-001")
                .location("Core Rack, Slot 1").status(HardwareStatus.IN_USE)
                .purchaseDate(LocalDate.now().minusYears(3))
                .warrantyExpiry(LocalDate.now().plusMonths(6))
                .lastMaintenanceDate(LocalDate.now().minusDays(60))
                .nextMaintenanceDate(LocalDate.now().plusDays(30))
                .notes("Primary layer-3 switch — connects all NEDI VLANs").build());

        hardwareRepository.save(Hardware.builder()
                .assetTag("NEDI-LB-001").name("NEDI Load Balancer Primary")
                .hardwareType(HardwareType.LOAD_BALANCER).manufacturer("F5")
                .model("BIG-IP 2000s").serialNumber("F5-LB-001")
                .location("DMZ Rack, Slot 3").status(HardwareStatus.IN_USE)
                .purchaseDate(LocalDate.now().minusYears(2))
                .warrantyExpiry(LocalDate.now().plusYears(1))
                .lastMaintenanceDate(LocalDate.now().minusDays(30))
                .nextMaintenanceDate(LocalDate.now().plusDays(60))
                .notes("Distributes traffic across Student and Exam portal web servers").build());

        hardwareRepository.save(Hardware.builder()
                .assetTag("NEDI-UPS-001").name("UPS Unit A — DB Rack")
                .hardwareType(HardwareType.UPS).manufacturer("APC")
                .model("Smart-UPS 3000").serialNumber("APC-UPS-001")
                .location("DB Rack A, Power Unit").status(HardwareStatus.IN_USE)
                .purchaseDate(LocalDate.now().minusYears(4))
                .warrantyExpiry(LocalDate.now().minusDays(10))
                .lastMaintenanceDate(LocalDate.now().minusDays(90))
                .nextMaintenanceDate(LocalDate.now().plusDays(0))
                .notes("UPS protecting Exam DB rack — WARRANTY EXPIRED, maintenance overdue").build());

        log.info("Seeded 3 NEDI hardware assets");
    }

    // ─────────────────────────────────────────────────────────────────
    // DIGITAL SERVICES — 8 NEDI services
    // ─────────────────────────────────────────────────────────────────
    private void seedDigitalServices() {

        digitalServiceRepository.save(DigitalService.builder()
                .serviceCode("STUDENT_PORTAL").name("Student Portal")
                .serviceType(ServiceType.STUDENT_PORTAL)
                .description("Student profile, fee payment, academic records, and attendance")
                .hostDomain("student.nedi.local")
                .institutionCode("NEDI-CENTRAL")
                .status(ServiceStatus.HEALTHY)
                .criticalityLevel(4).build());

        digitalServiceRepository.save(DigitalService.builder()
                .serviceCode("FACULTY_PORTAL").name("Faculty Portal")
                .serviceType(ServiceType.FACULTY_PORTAL)
                .description("Faculty attendance, course management, and evaluation workflow")
                .hostDomain("faculty.nedi.local")
                .institutionCode("NEDI-CENTRAL")
                .status(ServiceStatus.HEALTHY)
                .criticalityLevel(3).build());

        // EXAM PORTAL — intentionally HIGH_RISK for the demo scenario
        digitalServiceRepository.save(DigitalService.builder()
                .serviceCode("EXAM_PORTAL").name("Exam Portal")
                .serviceType(ServiceType.EXAM_PORTAL)
                .description("National examination system — high-impact, used by 500+ institutions")
                .hostDomain("exam.nedi.local")
                .institutionCode("NEDI-CENTRAL")
                .status(ServiceStatus.HIGH_RISK)
                .criticalityLevel(5).build());

        digitalServiceRepository.save(DigitalService.builder()
                .serviceCode("ERP").name("ERP System")
                .serviceType(ServiceType.ERP)
                .description("Finance, HR, operations, and administrative management")
                .hostDomain("erp.nedi.local")
                .institutionCode("NEDI-CENTRAL")
                .status(ServiceStatus.DEGRADED)
                .criticalityLevel(4).build());

        digitalServiceRepository.save(DigitalService.builder()
                .serviceCode("ADMISSION_PORTAL").name("Admission Portal")
                .serviceType(ServiceType.ADMISSION_PORTAL)
                .description("Student admission applications and document verification")
                .hostDomain("admission.nedi.local")
                .institutionCode("NEDI-CENTRAL")
                .status(ServiceStatus.HEALTHY)
                .criticalityLevel(3).build());

        digitalServiceRepository.save(DigitalService.builder()
                .serviceCode("DIGITAL_LIBRARY").name("Digital Library")
                .serviceType(ServiceType.DIGITAL_LIBRARY)
                .description("E-books, research papers, and digital resource access")
                .hostDomain("library.nedi.local")
                .institutionCode("NEDI-CENTRAL")
                .status(ServiceStatus.HEALTHY)
                .criticalityLevel(2).build());

        digitalServiceRepository.save(DigitalService.builder()
                .serviceCode("LMS").name("Learning Management System")
                .serviceType(ServiceType.LMS)
                .description("Online classes, assignments, quizzes, and course submissions")
                .hostDomain("lms.nedi.local")
                .institutionCode("NEDI-CENTRAL")
                .status(ServiceStatus.HEALTHY)
                .criticalityLevel(4).build());

        digitalServiceRepository.save(DigitalService.builder()
                .serviceCode("MAIL_SERVICE").name("Institutional Mail")
                .serviceType(ServiceType.MAIL_SERVICE)
                .description("Institutional email and identity-linked communication service")
                .hostDomain("mail.nedi.local")
                .institutionCode("NEDI-CENTRAL")
                .status(ServiceStatus.HEALTHY)
                .criticalityLevel(3).build());

        log.info("Seeded 8 NEDI digital services (Exam Portal = HIGH_RISK, ERP = DEGRADED)");
    }

    // ─────────────────────────────────────────────────────────────────
    // INSTITUTIONS — representative NEDI monitored organizations
    // ─────────────────────────────────────────────────────────────────
    private void seedInstitutions() {

        institutionRepository.save(Institution.builder()
                .institutionCode("NEDI-CENTRAL")
                .name("NEDI Central Operations")
                .type(InstitutionType.CENTRAL_OPERATIONS)
                .city("New Delhi")
                .state("Delhi")
                .region("National")
                .status(InstitutionStatus.ACTIVE)
                .studentCount(0)
                .servicesMonitored(8)
                .notes("Central SOC and digital infrastructure operations unit for the fictional NEDI scenario")
                .build());

        institutionRepository.save(Institution.builder()
                .institutionCode("COL-A-SOUTH")
                .name("College A - South Campus")
                .type(InstitutionType.ENGINEERING_COLLEGE)
                .city("Chennai")
                .state("Tamil Nadu")
                .region("South")
                .status(InstitutionStatus.ACTIVE)
                .studentCount(8400)
                .servicesMonitored(8)
                .notes("Representative institution using Student, Faculty, Exam, ERP, LMS, Library, Admission and Mail services")
                .build());

        institutionRepository.save(Institution.builder()
                .institutionCode("COL-B-WEST")
                .name("College B - Western Institute")
                .type(InstitutionType.ENGINEERING_COLLEGE)
                .city("Pune")
                .state("Maharashtra")
                .region("West")
                .status(InstitutionStatus.ACTIVE)
                .studentCount(6200)
                .servicesMonitored(8)
                .notes("Healthy institution in the NEDI monitoring scenario")
                .build());

        institutionRepository.save(Institution.builder()
                .institutionCode("UNI-C-NORTH")
                .name("University C - North Cluster")
                .type(InstitutionType.UNIVERSITY)
                .city("Jaipur")
                .state("Rajasthan")
                .region("North")
                .status(InstitutionStatus.DEGRADED)
                .studentCount(18500)
                .servicesMonitored(8)
                .notes("Representative degraded institution affected by Exam Portal latency during the demo")
                .build());

        institutionRepository.save(Institution.builder()
                .institutionCode("POLY-D-EAST")
                .name("Polytechnic D - East Campus")
                .type(InstitutionType.POLYTECHNIC)
                .city("Kolkata")
                .state("West Bengal")
                .region("East")
                .status(InstitutionStatus.ACTIVE)
                .studentCount(4100)
                .servicesMonitored(6)
                .notes("Smaller institution with partial service coverage")
                .build());

        institutionRepository.save(Institution.builder()
                .institutionCode("COL-E-CENTRAL")
                .name("College E - Central Region")
                .type(InstitutionType.ARTS_AND_SCIENCE_COLLEGE)
                .city("Bhopal")
                .state("Madhya Pradesh")
                .region("Central")
                .status(InstitutionStatus.HIGH_RISK)
                .studentCount(5300)
                .servicesMonitored(7)
                .notes("Representative institution impacted by the high-risk Exam Portal scenario")
                .build());

        log.info("Seeded 6 representative NEDI institutions");
    }

    // ─────────────────────────────────────────────────────────────────
    // GRAPH — attack path edges (BFS traversal)
    // ─────────────────────────────────────────────────────────────────
    private void seedGraph() {
        if (relationshipRepository.count() > 0) {
            log.debug("Graph edges already seeded — skipping");
            return;
        }

        java.util.function.Consumer<AssetRelationship> save = relationshipRepository::save;

        // ── USER → FIREWALL (entry points) ─────────────────────────
        // viewer (student user) → DMZ firewall — LOW TRUST (attack entry)
        save.accept(AssetRelationship.builder()
                .sourceAssetId(3L).sourceType(AssetType.USER)
                .targetAssetId(1L).targetType(AssetType.FIREWALL)
                .relationshipType(RelationshipType.CONNECTS_TO)
                .trustLevel(20).build());

        // serveradmin → Core firewall
        save.accept(AssetRelationship.builder()
                .sourceAssetId(2L).sourceType(AssetType.USER)
                .targetAssetId(2L).targetType(AssetType.FIREWALL)
                .relationshipType(RelationshipType.CONNECTS_TO)
                .trustLevel(70).build());

        // admin → DMZ firewall (management)
        save.accept(AssetRelationship.builder()
                .sourceAssetId(1L).sourceType(AssetType.USER)
                .targetAssetId(1L).targetType(AssetType.FIREWALL)
                .relationshipType(RelationshipType.MANAGES)
                .trustLevel(90).build());

        // ── FIREWALL → SERVER (pivot points) ───────────────────────
        // NEDI-DMZ-FW-01 → NEDI-STUDENT-WEB-01 (LOW trust — internet-facing)
        save.accept(AssetRelationship.builder()
                .sourceAssetId(1L).sourceType(AssetType.FIREWALL)
                .targetAssetId(1L).targetType(AssetType.SERVER)
                .relationshipType(RelationshipType.CONNECTS_TO)
                .trustLevel(25).build());

        // NEDI-DMZ-FW-01 → NEDI-ERP-APP-01
        save.accept(AssetRelationship.builder()
                .sourceAssetId(1L).sourceType(AssetType.FIREWALL)
                .targetAssetId(5L).targetType(AssetType.SERVER)
                .relationshipType(RelationshipType.CONNECTS_TO)
                .trustLevel(30).build());

        // NEDI-CORE-FW-01 → NEDI-EXAM-APP-01
        save.accept(AssetRelationship.builder()
                .sourceAssetId(2L).sourceType(AssetType.FIREWALL)
                .targetAssetId(2L).targetType(AssetType.SERVER)
                .relationshipType(RelationshipType.CONNECTS_TO)
                .trustLevel(50).build());

        // NEDI-DB-FW-01 → NEDI-EXAM-DB-01
        save.accept(AssetRelationship.builder()
                .sourceAssetId(3L).sourceType(AssetType.FIREWALL)
                .targetAssetId(3L).targetType(AssetType.SERVER)
                .relationshipType(RelationshipType.CONNECTS_TO)
                .trustLevel(60).build());

        // ── SERVER → SERVER (lateral movement) ─────────────────────
        // NEDI-STUDENT-WEB-01 → NEDI-EXAM-APP-01 (lateral pivot)
        save.accept(AssetRelationship.builder()
                .sourceAssetId(1L).sourceType(AssetType.SERVER)
                .targetAssetId(2L).targetType(AssetType.SERVER)
                .relationshipType(RelationshipType.CONNECTS_TO)
                .trustLevel(40).build());

        // NEDI-EXAM-APP-01 → NEDI-EXAM-DB-01 (CRITICAL lateral move)
        save.accept(AssetRelationship.builder()
                .sourceAssetId(2L).sourceType(AssetType.SERVER)
                .targetAssetId(3L).targetType(AssetType.SERVER)
                .relationshipType(RelationshipType.CONNECTS_TO)
                .trustLevel(55).build());

        // NEDI-FACULTY-WEB-01 → NEDI-EXAM-DB-01 (backup job)
        save.accept(AssetRelationship.builder()
                .sourceAssetId(4L).sourceType(AssetType.SERVER)
                .targetAssetId(3L).targetType(AssetType.SERVER)
                .relationshipType(RelationshipType.CONNECTS_TO)
                .trustLevel(45).build());

        // ── SERVER → LICENSE (dependencies) ────────────────────────
        save.accept(AssetRelationship.builder()
                .sourceAssetId(3L).sourceType(AssetType.SERVER)
                .targetAssetId(1L).targetType(AssetType.LICENSE)
                .relationshipType(RelationshipType.HOSTS)
                .trustLevel(80).build());

        save.accept(AssetRelationship.builder()
                .sourceAssetId(1L).sourceType(AssetType.SERVER)
                .targetAssetId(2L).targetType(AssetType.LICENSE)
                .relationshipType(RelationshipType.HOSTS)
                .trustLevel(80).build());

        // ── HARDWARE → SERVER (infrastructure) ─────────────────────
        save.accept(AssetRelationship.builder()
                .sourceAssetId(1L).sourceType(AssetType.HARDWARE)
                .targetAssetId(1L).targetType(AssetType.SERVER)
                .relationshipType(RelationshipType.CONNECTS_TO)
                .trustLevel(85).build());

        save.accept(AssetRelationship.builder()
                .sourceAssetId(2L).sourceType(AssetType.HARDWARE)
                .targetAssetId(1L).targetType(AssetType.SERVER)
                .relationshipType(RelationshipType.CONNECTS_TO)
                .trustLevel(75).build());

        save.accept(AssetRelationship.builder()
                .sourceAssetId(2L).sourceType(AssetType.HARDWARE)
                .targetAssetId(2L).targetType(AssetType.SERVER)
                .relationshipType(RelationshipType.CONNECTS_TO)
                .trustLevel(75).build());

        log.info("Seeded 15 graph edges — BFS path: viewer → NEDI-DMZ-FW-01 → NEDI-STUDENT-WEB-01 → NEDI-EXAM-APP-01 → NEDI-EXAM-DB-01");
    }

    // ─────────────────────────────────────────────────────────────────
    // LOAD BALANCERS & INGRESS LOAD BALANCERS
    // ─────────────────────────────────────────────────────────────────
    private void seedLoadBalancers() {
        // 1. Dual-Stack Ingress Edge Load Balancer
        LoadBalancer ingressLb = loadBalancerRepository.save(LoadBalancer.builder()
                .name("NEDI-INGRESS-LB-01 (External Edge Ingress)")
                .virtualIp("10.0.0.100")
                .algorithm(Algorithm.ROUND_ROBIN)
                .status(LbStatus.ACTIVE)
                .healthCheckPath("/healthz")
                .healthCheckIntervalSeconds(15)
                .notes("Dual-stack Layer-7 Ingress Gateway fronting public student & admission portals. TLS 1.3 termination, HTTP/2, WAF rule inspection, and ingress rate-limiting.")
                .build());

        loadBalancerBackendRepository.save(LoadBalancerBackend.builder()
                .loadBalancer(ingressLb).targetName("NEDI-STUDENT-WEB-01").targetIp("10.0.1.10").port(443).weight(3).healthy(true).build());
        loadBalancerBackendRepository.save(LoadBalancerBackend.builder()
                .loadBalancer(ingressLb).targetName("NEDI-STUDENT-WEB-02").targetIp("10.0.1.15").port(443).weight(3).healthy(true).build());
        loadBalancerBackendRepository.save(LoadBalancerBackend.builder()
                .loadBalancer(ingressLb).targetName("NEDI-ADMISSION-WEB-01").targetIp("10.0.1.25").port(443).weight(2).healthy(true).build());

        // 2. Exam Portal Edge Ingress LB
        LoadBalancer examLb = loadBalancerRepository.save(LoadBalancer.builder()
                .name("NEDI-EXAM-INGRESS-LB-02 (Exam Portal Edge Ingress)")
                .virtualIp("10.0.0.150")
                .algorithm(Algorithm.LEAST_CONNECTIONS)
                .status(LbStatus.DEGRADED)
                .healthCheckPath("/actuator/health")
                .healthCheckIntervalSeconds(10)
                .notes("Dedicated high-throughput Ingress Load Balancer for National Examination Platform. Traffic pinned with session persistence. Marked DEGRADED due to backend unpatched node latency & thread contention.")
                .build());

        loadBalancerBackendRepository.save(LoadBalancerBackend.builder()
                .loadBalancer(examLb).targetName("NEDI-EXAM-APP-01").targetIp("10.0.1.11").port(8443).weight(2).healthy(false).build());
        loadBalancerBackendRepository.save(LoadBalancerBackend.builder()
                .loadBalancer(examLb).targetName("NEDI-EXAM-APP-02").targetIp("10.0.1.18").port(8443).weight(4).healthy(true).build());

        // 3. Faculty & ERP Cluster LB
        LoadBalancer erpLb = loadBalancerRepository.save(LoadBalancer.builder()
                .name("NEDI-FACULTY-ERP-LB-01 (Administrative ERP & Faculty Cluster)")
                .virtualIp("10.0.1.210")
                .algorithm(Algorithm.ROUND_ROBIN)
                .status(LbStatus.MAINTENANCE)
                .healthCheckPath("/health")
                .healthCheckIntervalSeconds(30)
                .notes("Internal Layer-7 application load balancer distributing faculty portal and core ERP administrative microservices across campus private VLANs.")
                .build());

        loadBalancerBackendRepository.save(LoadBalancerBackend.builder()
                .loadBalancer(erpLb).targetName("NEDI-FACULTY-WEB-01").targetIp("10.0.1.13").port(80).weight(2).healthy(true).build());
        loadBalancerBackendRepository.save(LoadBalancerBackend.builder()
                .loadBalancer(erpLb).targetName("NEDI-ERP-APP-01").targetIp("10.0.1.14").port(8080).weight(1).healthy(false).build());

        // 4. DB Cluster Read-Replica LB
        LoadBalancer dbLb = loadBalancerRepository.save(LoadBalancer.builder()
                .name("NEDI-DB-CLUSTER-LB-01 (Database Read-Replica Proxy)")
                .virtualIp("10.0.1.220")
                .algorithm(Algorithm.LEAST_CONNECTIONS)
                .status(LbStatus.ACTIVE)
                .healthCheckPath("/db/ping")
                .healthCheckIntervalSeconds(20)
                .notes("Layer-4 TCP high-availability proxy balancing analytical queries, student transcript queries, and institutional reporting jobs across database read-replicas.")
                .build());

        loadBalancerBackendRepository.save(LoadBalancerBackend.builder()
                .loadBalancer(dbLb).targetName("NEDI-EXAM-DB-01").targetIp("10.0.1.12").port(1521).weight(1).healthy(true).build());
        loadBalancerBackendRepository.save(LoadBalancerBackend.builder()
                .loadBalancer(dbLb).targetName("NEDI-EXAM-DB-REPL-01").targetIp("10.0.1.22").port(1521).weight(2).healthy(true).build());

        // 5. Auth & SSO Ingress LB
        LoadBalancer authLb = loadBalancerRepository.save(LoadBalancer.builder()
                .name("NEDI-AUTH-SSO-LB-01 (Identity & SSO Ingress Gateway)")
                .virtualIp("10.0.0.180")
                .algorithm(Algorithm.IP_HASH)
                .status(LbStatus.ACTIVE)
                .healthCheckPath("/oauth2/health")
                .healthCheckIntervalSeconds(15)
                .notes("Zero-Trust SSO Ingress Load Balancer with client IP hashing for centralized OAuth2/OIDC campus identity federations and credential authentication.")
                .build());

        loadBalancerBackendRepository.save(LoadBalancerBackend.builder()
                .loadBalancer(authLb).targetName("NEDI-AUTH-NODE-01").targetIp("10.0.1.30").port(443).weight(1).healthy(true).build());
        loadBalancerBackendRepository.save(LoadBalancerBackend.builder()
                .loadBalancer(authLb).targetName("NEDI-AUTH-NODE-02").targetIp("10.0.1.31").port(443).weight(1).healthy(true).build());

        // 6. LMS & Media Streaming LB
        LoadBalancer lmsLb = loadBalancerRepository.save(LoadBalancer.builder()
                .name("NEDI-LMS-STREAM-LB-01 (Learning Management & Media CDN)")
                .virtualIp("10.0.0.190")
                .algorithm(Algorithm.WEIGHTED)
                .status(LbStatus.ACTIVE)
                .healthCheckPath("/streaming/health")
                .healthCheckIntervalSeconds(20)
                .notes("High-capacity media distribution balancer handling video streaming, virtual classroom feeds, digital library assets, and quiz synchronization.")
                .build());

        loadBalancerBackendRepository.save(LoadBalancerBackend.builder()
                .loadBalancer(lmsLb).targetName("NEDI-LMS-CORE-01").targetIp("10.0.1.40").port(8080).weight(3).healthy(true).build());
        loadBalancerBackendRepository.save(LoadBalancerBackend.builder()
                .loadBalancer(lmsLb).targetName("NEDI-LMS-CACHE-01").targetIp("10.0.1.41").port(8080).weight(5).healthy(true).build());

        log.info("Seeded 6 NEDI Load Balancers (Ingress & Internal) with 14 backend server targets");
    }

    // ─────────────────────────────────────────────────────────────────
    // SECURITY INCIDENTS — NIST SP 800-61 Lifecycle Coverage
    // ─────────────────────────────────────────────────────────────────
    private void seedIncidents() {
        var servers = serverRepository.findAll();
        Server examDb     = findServer(servers, "EXAM-DB");
        Server examApp    = findServer(servers, "EXAM-APP");
        Server studentWeb = findServer(servers, "STUDENT-WEB");
        Server facultyWeb = findServer(servers, "FACULTY-WEB");

        Long examDbId     = examDb != null ? examDb.getId() : 3L;
        Long examAppId    = examApp != null ? examApp.getId() : 2L;
        Long studentWebId = studentWeb != null ? studentWeb.getId() : 1L;
        Long facultyWebId = facultyWeb != null ? facultyWeb.getId() : 4L;

        // 1. CRITICAL - Lateral movement pivot (OPEN)
        incidentRepository.save(Incident.builder()
                .title("[CRITICAL] Lateral Movement Pivot: Student Portal Web to Exam Database")
                .description("Compromised identity 'viewer' established unauthorized foothold on DMZ web server (10.0.1.10). Attacker initiated network discovery probing internal subnet 10.0.1.0/24, attempting lateral movement pivot to unpatched Exam Application Server (10.0.1.11) and targeted staging against Exam DB (10.0.1.12).")
                .severity(Severity.CRITICAL)
                .status(IncidentStatus.OPEN)
                .relatedAssetId(examDbId)
                .relatedAssetType(AssetType.SERVER)
                .riskScore(96)
                .attackPath("viewer (USER) → NEDI-DMZ-FW-01 (FIREWALL) → NEDI-STUDENT-WEB-01 (SERVER) → NEDI-EXAM-APP-01 (SERVER) → NEDI-EXAM-DB-01 (SERVER)")
                .affectedUsername("viewer")
                .sourceIp("198.51.100.87")
                .remediationNotes("[10:14:02] Autonomous Risk Engine flagged critical score 96/100. [10:15:30] Perimeter alert dispatched to SOC On-Call. EDR agent isolated host outbound sockets.")
                .createdAt(LocalDateTime.now().minusHours(2))
                .build());

        // 2. HIGH - Credential Stuffing on SSO Ingress (OPEN)
        incidentRepository.save(Incident.builder()
                .title("[HIGH] Multi-Source Credential Stuffing on Single Sign-On Ingress")
                .description("Distributed brute-force attack detected originating from multi-homed botnet cluster. 480 rapid failed login attempts recorded within 180 seconds targeting administrative user 'serveradmin'. Account lockout sentinel activated pursuant to NIST SP 800-63B standards.")
                .severity(Severity.HIGH)
                .status(IncidentStatus.OPEN)
                .relatedAssetId(1L)
                .relatedAssetType(AssetType.USER)
                .riskScore(88)
                .attackPath("External Ingress → NEDI-AUTH-SSO-LB-01 → /api/auth/login → Account Lockout Sentinel")
                .affectedUsername("serveradmin")
                .sourceIp("203.0.113.195")
                .remediationNotes("[09:30:15] Threshold breach: 5 failed attempts in 60s. [09:32:00] Ingress rate-limiter engaged on SSO Load Balancer.")
                .createdAt(LocalDateTime.now().minusHours(4))
                .build());

        // 3. HIGH - Exploitation Probe on Exam App Server (INVESTIGATING)
        incidentRepository.save(Incident.builder()
                .title("[HIGH] Exploitation Probe on Unpatched Exam App Server (CentOS 7.9)")
                .description("Deep packet inspection identified serialized deserialization payload targeting known vulnerability CVE-2023-38606 on unpatched host NEDI-EXAM-APP-01 (patch lag >120 days). SOC analyst actively reviewing raw network capture and executing forensic memory audit.")
                .severity(Severity.HIGH)
                .status(IncidentStatus.INVESTIGATING)
                .relatedAssetId(examAppId)
                .relatedAssetType(AssetType.SERVER)
                .riskScore(85)
                .attackPath("External → NEDI-CORE-FW-01 → NEDI-EXAM-APP-01 (Port 8443)")
                .assignedTo("soc_lead")
                .sourceIp("45.33.32.156")
                .remediationNotes("[11:05:00] Triage initiated by soc_lead. Host isolated from peer subnets. Patch deployment scheduled for emergency change window.")
                .createdAt(LocalDateTime.now().minusHours(6))
                .build());

        // 4. HIGH - IDOR on Student Gradebook (INVESTIGATING)
        incidentRepository.save(Incident.builder()
                .title("[HIGH] Insecure Direct Object Reference (IDOR) on Student Gradebook API")
                .description("Authenticated session attempting sequential parameter enumeration against unassigned college server assets and confidential student records. Triggered OWASP Top 10 A01: Broken Access Control alert.")
                .severity(Severity.HIGH)
                .status(IncidentStatus.INVESTIGATING)
                .relatedAssetId(studentWebId)
                .relatedAssetType(AssetType.SERVER)
                .riskScore(82)
                .attackPath("viewer (USER) → /api/servers/3 → 403 Forbidden Access Control Sentinel")
                .affectedUsername("viewer")
                .assignedTo("incident_responder")
                .sourceIp("10.0.0.45")
                .remediationNotes("[12:20:10] Investigating analyst confirming tenant isolation rules and reviewing application access control list.")
                .createdAt(LocalDateTime.now().minusHours(8))
                .build());

        // 5. MEDIUM - Slowloris on Ingress LB (CONTAINED)
        incidentRepository.save(Incident.builder()
                .title("[MEDIUM] Slowloris DoS Attack on NEDI-INGRESS-LB-01 Pool")
                .description("Asymmetric HTTP connection exhaustion attack keeping connections half-open, causing thread pool contention and 35% latency increase on student admission endpoints.")
                .severity(Severity.MEDIUM)
                .status(IncidentStatus.CONTAINED)
                .relatedAssetId(1L)
                .relatedAssetType(AssetType.LOAD_BALANCER)
                .riskScore(74)
                .attackPath("External Ingress → NEDI-INGRESS-LB-01 (Virtual IP: 10.0.0.100) → Student Portal Pool")
                .sourceIp("185.220.101.5")
                .containedBy("serveradmin")
                .containedAt(LocalDateTime.now().minusHours(3))
                .remediationNotes("Contained: Tightened HTTP keep-alive timeouts to 5 seconds, enforced maximum concurrent connections per source IP on Ingress Load Balancer, and blacklisted attacker subnet at upstream edge firewall.")
                .createdAt(LocalDateTime.now().minusHours(12))
                .build());

        // 6. MEDIUM - SQL Injection on College Portal (CONTAINED)
        incidentRepository.save(Incident.builder()
                .title("[MEDIUM] SQL Injection Beacon Detected — College A - South Campus")
                .description("College site beacon telemetry reported automated SQL injection exploitation attempt (' OR '1'='1' UNION SELECT ...) against student query input forms.")
                .severity(Severity.MEDIUM)
                .status(IncidentStatus.CONTAINED)
                .relatedAssetId(studentWebId)
                .relatedAssetType(AssetType.SERVER)
                .riskScore(72)
                .attackPath("External → College A South Campus → NEDI-STUDENT-WEB-01")
                .sourceIp("192.0.2.144")
                .containedBy("soc_lead")
                .containedAt(LocalDateTime.now().minusHours(5))
                .remediationNotes("Contained: Edge WAF signature rule #40012 pushed across all DMZ reverse proxies. Parameterized query enforcement verified.")
                .createdAt(LocalDateTime.now().minusHours(16))
                .build());

        // 7. LOW - Database License Expiry Violation (RESOLVED)
        incidentRepository.save(Incident.builder()
                .title("[LOW] Compliance Violation: Critical Database Software License Expired")
                .description("Automated compliance audit discovered Oracle Database 19c Enterprise license expired by 30 days without vendor maintenance contract renewal, exposing critical exam storage to compliance sanctions.")
                .severity(Severity.LOW)
                .status(IncidentStatus.RESOLVED)
                .relatedAssetId(1L)
                .relatedAssetType(AssetType.LICENSE)
                .riskScore(58)
                .attackPath("Internal Compliance Scanner → NEDI-EXAM-DB-01 → Oracle Licensing Service")
                .sourceIp("10.0.1.1")
                .resolvedBy("admin")
                .resolvedAt(LocalDateTime.now().minusDays(1))
                .remediationNotes("Resolved: Emergency procurement purchase order PO-88341 executed with Oracle enterprise sales. Valid license key applied and verified in repository.")
                .createdAt(LocalDateTime.now().minusDays(2))
                .build());

        // 8. MEDIUM - Rogue SSH Dictionary Attack (RESOLVED)
        incidentRepository.save(Incident.builder()
                .title("[MEDIUM] Rogue SSH Brute-Force Attempt via Admin Management Subnet")
                .description("Unauthorized workstation on administrative VLAN attempting rapid SSH dictionary password cracking against Faculty Web server root account.")
                .severity(Severity.MEDIUM)
                .status(IncidentStatus.RESOLVED)
                .relatedAssetId(facultyWebId)
                .relatedAssetType(AssetType.SERVER)
                .riskScore(70)
                .attackPath("Management Subnet (10.0.0.220) → NEDI-CORE-FW-01 → NEDI-FACULTY-WEB-01 (Port 22)")
                .affectedUsername("root")
                .sourceIp("10.0.0.220")
                .resolvedBy("net_admin")
                .resolvedAt(LocalDateTime.now().minusDays(2))
                .remediationNotes("Resolved: Identified rogue testing machine in engineering lab. Port 22 password authentication disabled in sshd_config; enforced hardware-bound ED25519 SSH keys only.")
                .createdAt(LocalDateTime.now().minusDays(3))
                .build());

        log.info("Seeded 8 NEDI Security Incidents across OPEN, INVESTIGATING, CONTAINED, and RESOLVED stages");
    }

    // ─────────────────────────────────────────────────────────────────
    // AUDIT LOGS — URLs & Multi-User Traceability
    // ─────────────────────────────────────────────────────────────────
    private void seedAuditLogs() {
        LocalDateTime now = LocalDateTime.now();

        record LogEntry(Long userId, String username, Action action, AuditLog.TargetType targetType,
                        Long targetId, String ip, String url, String detail, int minutesAgo) {}

        List<LogEntry> entries = List.of(
            // Admin operations
            new LogEntry(1L, "admin", Action.LOGIN_OK, AuditLog.TargetType.USER, 1L, "10.0.0.15", "POST /api/auth/login", "SOC Admin authenticated via hardware 2FA token", 5),
            new LogEntry(1L, "admin", Action.READ, AuditLog.TargetType.INCIDENT, 1L, "10.0.0.15", "GET /api/incidents/1", "Reviewing Incident #1 threat telemetry and ATT&CK graph", 8),
            new LogEntry(1L, "admin", Action.UPDATE, AuditLog.TargetType.INCIDENT, 1L, "10.0.0.15", "PUT /api/incidents/1/notes", "Appended forensic memory acquisition note", 12),
            new LogEntry(1L, "admin", Action.READ, AuditLog.TargetType.LOAD_BALANCER, null, "10.0.0.15", "GET /api/loadbalancers", "Inspected Ingress and application load balancer telemetry", 18),
            new LogEntry(1L, "admin", Action.CREATE, AuditLog.TargetType.LOAD_BALANCER, 1L, "10.0.0.15", "POST /api/loadbalancers", "Provisioned NEDI-INGRESS-LB-01 edge load balancer", 140),

            // SOC Lead operations
            new LogEntry(3L, "soc_lead", Action.LOGIN_OK, AuditLog.TargetType.USER, 3L, "10.0.0.28", "POST /api/auth/login", "SOC Lead analyst login session established", 25),
            new LogEntry(3L, "soc_lead", Action.UPDATE, AuditLog.TargetType.INCIDENT, 3L, "10.0.0.28", "PUT /api/incidents/3/investigate", "Assigned investigation of CVE-2023-38606 on Exam App Server", 30),
            new LogEntry(3L, "soc_lead", Action.UPDATE, AuditLog.TargetType.INCIDENT, 6L, "10.0.0.28", "PUT /api/incidents/6/contain", "Applied WAF query rule to contain college SQL injection", 45),
            new LogEntry(3L, "soc_lead", Action.READ, AuditLog.TargetType.INCIDENT, 1L, "10.0.0.28", "GET /api/reports/incident/1/pdf", "Generated NIST SP 800-61 forensic incident PDF report", 50),

            // Server Admin operations
            new LogEntry(2L, "serveradmin", Action.LOGIN_OK, AuditLog.TargetType.USER, 2L, "10.0.1.4", "POST /api/auth/login", "Infrastructure engineer logged in from management subnet", 60),
            new LogEntry(2L, "serveradmin", Action.UPDATE, AuditLog.TargetType.LOAD_BALANCER, 1L, "10.0.1.4", "PUT /api/loadbalancer-backends/2/health", "Backend NEDI-STUDENT-WEB-02 marked HEALTHY after maintenance", 75),
            new LogEntry(2L, "serveradmin", Action.UPDATE, AuditLog.TargetType.INCIDENT, 5L, "10.0.1.4", "PUT /api/incidents/5/contain", "Adjusted ingress keep-alive timeout to 5s to mitigate Slowloris", 90),
            new LogEntry(2L, "serveradmin", Action.UPDATE, AuditLog.TargetType.SERVER, 2L, "10.0.1.4", "PUT /api/servers/2", "Scheduled patch kernel window for NEDI-EXAM-APP-01", 110),

            // Network Admin operations
            new LogEntry(4L, "net_admin", Action.LOGIN_OK, AuditLog.TargetType.USER, 4L, "10.0.0.35", "POST /api/auth/login", "Network Admin session authenticated", 120),
            new LogEntry(4L, "net_admin", Action.CREATE, AuditLog.TargetType.FIREWALL_RULE, 26L, "10.0.0.35", "POST /api/firewall-rules", "Added perimeter edge firewall drop rule for malicious IP block", 135),
            new LogEntry(4L, "net_admin", Action.UPDATE, AuditLog.TargetType.INCIDENT, 8L, "10.0.0.35", "PUT /api/incidents/8/resolve", "Disabled SSH password authentication and closed rogue port 22 access", 160),

            // DB Admin operations
            new LogEntry(5L, "db_admin", Action.LOGIN_OK, AuditLog.TargetType.USER, 5L, "10.0.1.55", "POST /api/auth/login", "Database Administrator signed in", 180),
            new LogEntry(5L, "db_admin", Action.READ, AuditLog.TargetType.SERVER, 3L, "10.0.1.55", "GET /api/servers/3", "Inspected Exam DB connection pool metrics and active sessions", 195),
            new LogEntry(5L, "db_admin", Action.CREATE, AuditLog.TargetType.LOAD_BALANCER, 4L, "10.0.1.55", "POST /api/loadbalancers/4/backends", "Added NEDI-EXAM-DB-REPL-01 read-replica backend to DB load balancer", 220),

            // Incident Responder operations
            new LogEntry(6L, "incident_responder", Action.LOGIN_OK, AuditLog.TargetType.USER, 6L, "10.0.0.62", "POST /api/auth/login", "Tier 2 IR responder authenticated", 240),
            new LogEntry(6L, "incident_responder", Action.UPDATE, AuditLog.TargetType.INCIDENT, 4L, "10.0.0.62", "PUT /api/incidents/4/investigate", "Initiated IDOR access pattern audit across student endpoints", 260),

            // Cloud Engineer operations
            new LogEntry(7L, "cloud_engineer", Action.LOGIN_OK, AuditLog.TargetType.USER, 7L, "10.0.1.80", "POST /api/auth/login", "Cloud engineer logged in", 300),
            new LogEntry(7L, "cloud_engineer", Action.CREATE, AuditLog.TargetType.LOAD_BALANCER, 5L, "10.0.1.80", "POST /api/loadbalancers", "Configured NEDI-AUTH-SSO-LB-01 Ingress load balancer", 320),

            // Compliance Auditor operations
            new LogEntry(8L, "compliance_auditor", Action.LOGIN_OK, AuditLog.TargetType.USER, 8L, "10.0.2.14", "POST /api/auth/login", "Governance auditor read-only session started", 360),
            new LogEntry(8L, "compliance_auditor", Action.READ, AuditLog.TargetType.LICENSE, null, "10.0.2.14", "GET /api/licenses", "Conducted license compliance and regulatory renewal audit", 380),
            new LogEntry(8L, "compliance_auditor", Action.READ, AuditLog.TargetType.INCIDENT, null, "10.0.2.14", "GET /api/incidents", "Audited security incident SLA closure and containment times", 400),

            // Student/Viewer Portal & Compromised Account Activity
            new LogEntry(10L, "viewer", Action.LOGIN_OK, AuditLog.TargetType.USER, 10L, "10.0.0.99", "POST /api/auth/login", "Viewer session logged in from campus terminal", 420),
            new LogEntry(10L, "viewer", Action.READ, AuditLog.TargetType.SERVER, 1L, "10.0.0.99", "GET /api/servers/1", "Retrieved Student Web portal operational status", 425),
            new LogEntry(10L, "viewer", Action.READ, AuditLog.TargetType.SERVER, 3L, "10.0.0.99", "GET /api/servers/3", "IDOR probe blocked: unauthorized access to NEDI-EXAM-DB-01", 430),

            // Adversary / Brute Force Attack Activity
            new LogEntry(null, "admin", Action.LOGIN_FAIL, AuditLog.TargetType.USER, null, "203.0.113.195", "POST /api/auth/login", "Failed login: invalid credential attempt from external IP", 480),
            new LogEntry(null, "admin", Action.LOGIN_FAIL, AuditLog.TargetType.USER, null, "203.0.113.195", "POST /api/auth/login", "Failed login: repeated password spray attempt", 481),
            new LogEntry(null, "serveradmin", Action.LOGIN_FAIL, AuditLog.TargetType.USER, null, "203.0.113.195", "POST /api/auth/login", "Failed login: credential stuffing dictionary hit", 482),
            new LogEntry(null, "root", Action.LOGIN_FAIL, AuditLog.TargetType.USER, null, "10.0.0.220", "POST /api/auth/login", "Failed login: disallowed root login attempt from subnet", 500)
        );

        for (var e : entries) {
            AuditLog logEntry = AuditLog.builder()
                    .userId(e.userId)
                    .attemptedUsername(e.username)
                    .action(e.action)
                    .targetType(e.targetType)
                    .targetAssetId(e.targetId)
                    .ipAddress(e.ip)
                    .requestUrl(e.url)
                    .detail(e.detail)
                    .timestamp(now.minusMinutes(e.minutesAgo))
                    .build();
            auditLogRepository.save(logEntry);
        }

        log.info("Seeded {} audit logs with request URLs across 10 diverse user identities and external IPs", entries.size());
    }
}
