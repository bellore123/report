package com.cybershield.repository;

import com.cybershield.model.DigitalService;
import com.cybershield.model.DigitalService.ServiceStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface DigitalServiceRepository extends JpaRepository<DigitalService, Long> {
    Optional<DigitalService> findByServiceCode(String serviceCode);
    List<DigitalService> findByStatus(ServiceStatus status);
    long countByStatus(ServiceStatus status);
    long countByCriticalityLevelGreaterThanEqual(int criticalityLevel);
}
