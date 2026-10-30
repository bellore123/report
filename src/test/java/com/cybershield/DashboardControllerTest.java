package com.cybershield;

import com.cybershield.security.JwtUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class DashboardControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtUtil jwtUtil;

    @Test
    @DisplayName("1. Dashboard endpoint returns 200 and all required telemetry for ADMIN")
    void testGetDashboardAdmin() throws Exception {
        String token = jwtUtil.generateToken("admin", "ADMIN");

        mockMvc.perform(get("/api/dashboard")
                        .header("Authorization", "Bearer " + token)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.counts.totalServers").isNumber())
                .andExpect(jsonPath("$.counts.totalFirewalls").isNumber())
                .andExpect(jsonPath("$.counts.totalLicenses").isNumber())
                .andExpect(jsonPath("$.services").isArray())
                .andExpect(jsonPath("$.institutions").isArray())
                .andExpect(jsonPath("$.unpatchedServers").isArray())
                .andExpect(jsonPath("$.expiredLicenses").isArray())
                .andExpect(jsonPath("$.complianceScore").isNumber());
    }

    @Test
    @DisplayName("2. Dashboard endpoint accessible by VIEWER role")
    void testGetDashboardViewer() throws Exception {
        String token = jwtUtil.generateToken("viewer", "VIEWER");

        mockMvc.perform(get("/api/dashboard")
                        .header("Authorization", "Bearer " + token)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.counts").exists());
    }

    @Test
    @DisplayName("3. Unauthenticated request to dashboard returns 401")
    void testGetDashboardUnauthenticated() throws Exception {
        mockMvc.perform(get("/api/dashboard")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isUnauthorized());
    }
}
