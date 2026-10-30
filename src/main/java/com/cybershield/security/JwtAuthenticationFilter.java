package com.cybershield.security;

import com.cybershield.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JwtAuthenticationFilter — runs once per request to validate JWT tokens.
 *
 * Flow:
 *  1. Extract "Authorization: Bearer <token>" header
 *  2. Validate the token using JwtUtil (signature + expiry check)
 *  3. If valid → set authentication in SecurityContext (Spring Security trusts this request)
 *  4. If invalid → do nothing (Spring Security will block access with 401)
 *
 * This filter is the security gate that blocks Attack #3 (JWT tampering):
 * A tampered token will fail step 2 and never reach the controller.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String token = extractTokenFromRequest(request);

        if (token != null && jwtUtil.validateToken(token)) {
            String username = jwtUtil.extractUsername(token);
            String role = jwtUtil.extractRole(token);

            // Dynamically check database for real-time role and active status
            var userOpt = userRepository.findByUsername(username);
            if (userOpt.isPresent()) {
                var dbUser = userOpt.get();
                if (!dbUser.isActive()) {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\":\"Account is deactivated\"}");
                    return;
                }
                if (dbUser.getRole() != null) {
                    role = dbUser.getRole().name();
                }
            }

            // Create a UserDetails principal so @AuthenticationPrincipal UserDetails
            // works consistently in controllers.
            UserDetails principal = User.withUsername(username)
                    .password("")
                    .authorities(List.of(new SimpleGrantedAuthority("ROLE_" + role)))
                    .build();

            // Create Spring Security authentication object.
            // Role must be prefixed with "ROLE_" for Spring Security.
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            principal,
                            null,
                            principal.getAuthorities()
                    );

            authentication.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request)
            );

            // Tell Spring Security this request is authenticated
            SecurityContextHolder.getContext().setAuthentication(authentication);

            log.debug("JWT valid for user='{}' with role='{}'", username, role);
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Extract the JWT from the "Authorization: Bearer <token>" header.
     * Returns null if the header is missing or not in Bearer format.
     */
    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); // remove "Bearer " prefix
        }
        String paramToken = request.getParameter("token");
        if (StringUtils.hasText(paramToken)) {
            return paramToken;
        }
        return null;
    }
}
