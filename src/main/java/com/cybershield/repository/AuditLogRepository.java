package com.cybershield.repository;

import com.cybershield.model.AuditLog;
import com.cybershield.model.AuditLog.Action;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

/**
 * AuditLogRepository — database access for AuditLog entity.
 *
 * Key queries used by the Risk Engine:
 *   - Count failed logins in a time window (brute-force detection)
 *   - Get recent actions by a user (behavioral analysis)
 */
@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    // Find all logs for a specific user (for audit trail page)
    List<AuditLog> findByUserIdOrderByTimestampDesc(Long userId);

    // Count failed logins for a username in the last N minutes
    // Used by Risk Engine to detect brute-force attacks
    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.attemptedUsername = :username " +
           "AND a.action = 'LOGIN_FAIL' AND a.timestamp >= :since")
    long countFailedLoginsSince(@Param("username") String username,
                                @Param("since") LocalDateTime since);

    // FIX 1D: Count failed logins for a server's owner username in last 24h
    // Used to raise server risk when its owner account is under attack
    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.attemptedUsername = :ownerUsername " +
           "AND a.action = 'LOGIN_FAIL' AND a.timestamp >= :since")
    long countFailedLoginsForOwner(@Param("ownerUsername") String ownerUsername,
                                   @Param("since") LocalDateTime since);

    // Count failed logins from a specific IP in the last N minutes
    // Used to detect distributed brute-force / credential stuffing
    @Query("SELECT COUNT(a) FROM AuditLog a WHERE a.ipAddress = :ip " +
           "AND a.action = 'LOGIN_FAIL' AND a.timestamp >= :since")
    long countFailedLoginsFromIpSince(@Param("ip") String ip,
                                      @Param("since") LocalDateTime since);

    // Get recent audit logs (for the dashboard live feed and audit trail)
    List<AuditLog> findTop100ByOrderByTimestampDesc();
    List<AuditLog> findTop50ByOrderByTimestampDesc();

    // Get all logs by action type
    List<AuditLog> findByActionOrderByTimestampDesc(Action action);
}
