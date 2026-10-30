package com.cybershield;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * CyberShield Nexus main application entry point.
 *
 * Product: CyberShield Nexus
 * Scenario: NEDI - National Education Digital Infrastructure
 *
 * NEDI is a fictional academic demo scenario. Scheduling enables the
 * automatic risk scan used by the security command center workflow.
 */
@SpringBootApplication
@EnableScheduling
public class CyberShieldNexusApplication {

    public static void main(String[] args) {
        SpringApplication.run(CyberShieldNexusApplication.class, args);
    }
}
