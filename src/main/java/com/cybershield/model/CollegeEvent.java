package com.cybershield.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * CollegeEvent — an in-memory record of an attack/access event
 * received from one of the college-site beacons.
 *
 * NOT persisted to DB — stored in CollegeEventService's rolling
 * in-memory list (last 200 events). Incidents are persisted via
 * the existing IncidentService when risk threshold is exceeded.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CollegeEvent {

    private String id;                  // UUID

    /** Which college fired this event */
    private String institutionCode;     // e.g. "COL-A-SOUTH"
    private String collegeName;         // e.g. "College A - South Campus"
    private String collegeCity;         // e.g. "Chennai, Tamil Nadu"

    /** Which page / service triggered the event */
    private String page;                // "login", "exam", "faculty", "admin", "erp"
    private String eventType;           // LOGIN_ATTEMPT, SQL_INJECTION, BRUTE_FORCE, RECON, EXAM_ACCESS, FACULTY_ACCESS

    /** Server details — mapped from the college+page combination */
    private Long   serverId;
    private String serverIp;
    private String serverName;

    /** Attacker info */
    private String attackerIp;
    private String userAgent;
    private String inputPayload;        // raw form field value (for SQL injection detection)

    /** Computed risk */
    private int    riskScore;
    private String severity;            // LOW / MEDIUM / HIGH / CRITICAL
    private String attackPattern;       // what was detected
    private boolean incidentCreated;
    private Long   incidentId;

    private LocalDateTime timestamp;
}
