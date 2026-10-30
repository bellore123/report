package com.cybershield.repository;

import com.cybershield.model.Incident;
import com.cybershield.model.Incident.IncidentStatus;
import com.cybershield.model.Incident.Severity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * IncidentRepository — queries for incident management and dashboard display.
 */
@Repository
public interface IncidentRepository extends JpaRepository<Incident, Long> {

    // Dashboard: open incidents newest first
    List<Incident> findByStatusOrderByCreatedAtDesc(IncidentStatus status);

    // Dashboard & Incident Console: all incidents newest first
    List<Incident> findAllByOrderByCreatedAtDesc();

    // Dashboard: recent incidents regardless of status (pageable)
    List<Incident> findTop20ByOrderByCreatedAtDesc();

    // Filter by severity
    List<Incident> findBySeverityOrderByCreatedAtDesc(Severity severity);

    // Count open incidents (dashboard alert badge)
    long countByStatus(IncidentStatus status);

    // FIX 1B — correct duplicate check for SERVER incidents by assetId
    boolean existsByRelatedAssetIdAndStatusIn(Long assetId, List<IncidentStatus> statuses);

    // FIX 1B — correct duplicate check for USER incidents by username
    boolean existsByAffectedUsernameAndStatusIn(String username, List<IncidentStatus> statuses);
}
