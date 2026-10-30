package com.cybershield;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * Smoke test -- verifies the entire Spring context loads without errors.
 *
 * Uses the 'test' profile which configures H2 in-memory database,
 * so this test runs without a PostgreSQL connection.
 *
 * Run with: mvn test
 */
@SpringBootTest
@ActiveProfiles("test")
class CyberShieldNexusApplicationTests {

    @Test
    void contextLoads() {
        // Passes if the entire Spring context (Security, JPA, JWT, all beans)
        // wires up correctly with H2 in-memory database.
    }
}
