package com.cybershield.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

/**
 * JwtUtil — generates and validates JSON Web Tokens (JWT).
 *
 * Security Design:
 *   - Algorithm: HMAC-SHA256 (HS256) — symmetric key signing
 *   - The secret key is stored server-side only (never sent to client)
 *   - Any modification to the token payload INVALIDATES the signature
 *   - This is what blocks Attack #3 (JWT tampering) in the patched version
 *
 * Token payload (claims):
 *   - sub: username
 *   - role: user's role (ADMIN / SERVER_ADMIN / VIEWER)
 *   - iat: issued at timestamp
 *   - exp: expiry timestamp (24 hours by default)
 */
@Component
@Slf4j
public class JwtUtil {

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.expiration-ms}")
    private long jwtExpirationMs;

    /**
     * Build the SecretKey from the configured secret string.
     * The key is derived from the configured secret string.
     */
    private SecretKey getSigningKey() {
        byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Generate a JWT for a successfully authenticated user.
     *
     * @param username The authenticated username
     * @param role     The user's role (embedded in token as a claim)
     * @return Signed JWT string
     */
    public String generateToken(String username, String role) {
        return Jwts.builder()
                .subject(username)
                .claim("role", role)           // role embedded in token
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(getSigningKey())     // sign with HMAC-SHA256
                .compact();
    }

    /**
     * Extract the username from a valid token.
     */
    public String extractUsername(String token) {
        return parseClaims(token).getSubject();
    }

    /**
     * Extract the role claim from a valid token.
     */
    public String extractRole(String token) {
        return parseClaims(token).get("role", String.class);
    }

    /**
     * Validate the token — checks signature AND expiry.
     *
     * SECURITY NOTE: This is what makes Attack #3 (JWT tampering) fail
     * in the patched version. If the attacker modifies any claim and replays
     * the token, the signature will not match the server's key and this
     * method will throw an exception → 401 Unauthorized.
     *
     * @param token The JWT string from the Authorization header
     * @return true if valid, false if invalid or expired
     */
    public boolean validateToken(String token) {
        try {
            parseClaims(token); // throws if invalid
            return true;
        } catch (ExpiredJwtException e) {
            log.warn("JWT expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.warn("JWT unsupported: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.warn("JWT malformed: {}", e.getMessage());
        } catch (SecurityException e) {
            // This is thrown when signature verification fails
            // i.e., when Attack #3 (tampered token) is attempted
            log.warn("JWT signature invalid — possible tampering attempt: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.warn("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }

    /**
     * Parse and return all claims from a token.
     * Throws an exception if the token is invalid or expired.
     */
    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
