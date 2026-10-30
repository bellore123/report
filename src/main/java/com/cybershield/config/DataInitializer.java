package com.cybershield.config;

import com.cybershield.model.User;
import com.cybershield.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * DataInitializer — seeds initial data on application startup.
 *
 * On first run:
 *   - Creates the default ADMIN user: admin / Admin@123
 *   - Creates a test SERVER_ADMIN user: serveradmin / Admin@123
 *   - Creates a test VIEWER user: viewer / Admin@123
 *
 * These are the accounts used in our attack demonstrations.
 * The 'viewer' account is used for Attack #2 (IDOR) and Attack #3 (JWT tampering).
 *
 * IMPORTANT: In production, disable this class and use a proper onboarding flow.
 */
@Component
@Order(1)
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        // Core accounts for demonstrations and attack scenarios
        seedUser("admin",              "admin@cybershield.local",        "Admin@123", User.Role.ADMIN,        "IT Security & CISO");
        seedUser("serveradmin",        "serveradmin@cybershield.local",  "Admin@123", User.Role.SERVER_ADMIN, "Infrastructure & Cloud Ops");
        seedUser("viewer",             "viewer@cybershield.local",       "Admin@123", User.Role.VIEWER,       "Student Monitoring");

        // Expanded operational, SOC, and compliance personnel across NEDI infrastructure
        seedUser("soc_lead",           "soc.lead@cybershield.local",     "Admin@123", User.Role.ADMIN,        "Cyber Defense / SOC");
        seedUser("net_admin",          "net.admin@cybershield.local",    "Admin@123", User.Role.SERVER_ADMIN, "Network Engineering");
        seedUser("db_admin",           "db.admin@cybershield.local",     "Admin@123", User.Role.SERVER_ADMIN, "Database Operations");
        seedUser("incident_responder", "responder@cybershield.local",    "Admin@123", User.Role.SERVER_ADMIN, "Incident Response Team");
        seedUser("cloud_engineer",     "cloud.eng@cybershield.local",    "Admin@123", User.Role.SERVER_ADMIN, "Cloud Operations");
        seedUser("compliance_auditor", "compliance@cybershield.local",   "Admin@123", User.Role.VIEWER,       "Governance & Compliance");
        seedUser("academic_lead",      "academic.lead@cybershield.local","Admin@123", User.Role.VIEWER,       "Academic Services");
        seedUser("exam_coordinator",   "exam.coord@cybershield.local",   "Admin@123", User.Role.VIEWER,       "Examination Authority");
        seedUser("guest_auditor",      "auditor@cybershield.local",      "Admin@123", User.Role.VIEWER,       "External Security Audit");

        log.info("===========================================================");
        log.info("  CyberShield Nexus is ready!");
        log.info("  API running at: http://localhost:8081");
        log.info("  Default accounts (all passwords: Admin@123):");
        log.info("    admin, soc_lead                         → ADMIN role");
        log.info("    serveradmin, net_admin, db_admin, etc.  → SERVER_ADMIN role");
        log.info("    viewer, compliance_auditor, etc.        → VIEWER role");
        log.info("===========================================================");
    }

    private void seedUser(String username, String email,
                          String rawPassword, User.Role role, String department) {
        if (!userRepository.existsByUsername(username)) {
            User user = User.builder()
                    .username(username)
                    .email(email)
                    .passwordHash(passwordEncoder.encode(rawPassword))
                    .role(role)
                    .department(department)
                    .isActive(true)
                    .failedLoginAttempts(0)
                    .build();
            userRepository.save(user);
            log.info("Created user: '{}' with role '{}'", username, role);
        } else {
            log.debug("User '{}' already exists — skipping seed", username);
        }
    }
}
