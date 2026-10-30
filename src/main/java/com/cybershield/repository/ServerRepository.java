package com.cybershield.repository;

import com.cybershield.model.Server;
import com.cybershield.model.Server.ServerStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;

@Repository
public interface ServerRepository extends JpaRepository<Server, Long> {

    List<Server> findByStatus(ServerStatus status);

    // Risk Engine: find servers not patched in the last 90 days
    @Query("SELECT s FROM Server s WHERE s.lastPatchDate < :cutoffDate OR s.lastPatchDate IS NULL")
    List<Server> findUnpatchedServersBefore(LocalDate cutoffDate);

    // Dashboard: count by status
    long countByStatus(ServerStatus status);

    boolean existsByIpAddress(String ipAddress);

    java.util.Optional<Server> findByName(String name);

    // Used by AssetDataSeeder to detect old pre-Phase2 generic server names
    boolean existsByNameContaining(String namePart);
}
