package com.cybershield.config;

import com.cybershield.security.JwtAuthenticationFilter;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * SecurityConfig — defines the entire Spring Security configuration.
 *
 * Key decisions:
 *   - STATELESS sessions (JWT only, no HTTP sessions / cookies)
 *   - /api/auth/** is publicly accessible (login endpoint)
 *   - All other /api/** routes require a valid JWT
 *   - @EnableMethodSecurity allows @PreAuthorize on individual controller methods
 *     (used for role-based access control — VIEWER can only read, not create/delete)
 *   - BCrypt strength=12 for password hashing
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)   // enables @PreAuthorize annotations
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Disable CSRF (not needed for stateless REST APIs with JWT)
            .csrf(AbstractHttpConfigurer::disable)

            // Disable default form login and HTTP Basic (we use JWT)
            .formLogin(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)

            // Stateless session — Spring Security won't create HTTP sessions
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            // URL-level access rules
            .authorizeHttpRequests(auth -> auth
                // Public endpoints — no JWT required
                .requestMatchers("/api/auth/login").permitAll()
                .requestMatchers("/api/auth/register").permitAll()
                // College site event beacons — must be public (no JWT on college sites)
                .requestMatchers("/api/college-events", "/api/college-events/**").permitAll()
                // Static frontend files — no auth needed (JWT checked by JS)
                .requestMatchers("/", "/index.html", "/login.html", "/dashboard.html",
                                 "/servers.html", "/firewalls.html", "/loadbalancers.html",
                                 "/licenses.html", "/hardware.html",
                                 "/incidents.html", "/risk.html",
                                 "/audit-log.html", "/phishing-detector.html",
                                 "/users.html",
                                 "/css/**", "/js/**", "/img/**",
                                 "/favicon.ico",
                                 "/h2-console/**").permitAll()
                // Everything else requires authentication
                .anyRequest().authenticated()
            )

            // Allow frames from same origin for H2 Web Console
            .headers(headers -> headers.frameOptions(frameOptions -> frameOptions.sameOrigin()))

            // Clean JSON response on 403 Access Denied
            .exceptionHandling(ex -> ex
                // A missing or invalid JWT is an authentication failure, not a
                // permission failure. Returning 401 lets the frontend clear a
                // stale session and send the user back to the login page.
                .authenticationEntryPoint((request, response, authenticationException) -> {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\":\"Authentication required. Please log in again.\"}");
                })
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\":\"Access Denied: You do not have permission to perform this action\"}");
                })
            )

            // Add our JWT filter BEFORE Spring's default username/password filter
            .addFilterBefore(jwtAuthenticationFilter,
                             UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * BCryptPasswordEncoder — used to hash passwords before storing in DB.
     * Strength 12 = 2^12 = 4096 iterations (strong, but still fast enough for login).
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    /**
     * AuthenticationManager — needed by AuthService to authenticate users.
     */
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
