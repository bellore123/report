package com.cybershield.service;

import com.cybershield.model.DigitalService;
import com.cybershield.model.DigitalService.ServiceStatus;
import com.cybershield.repository.DigitalServiceRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * DigitalServiceService — business logic for NEDI digital services.
 *
 * The dashboard uses this service to show per-service health summary.
 * Service status is seeded initially and can be updated by the admin.
 */
@Service
@RequiredArgsConstructor
public class DigitalServiceService {

    private final DigitalServiceRepository digitalServiceRepository;

    public List<DigitalService> getAllServices() {
        return digitalServiceRepository.findAll();
    }

    public long countTotal() {
        return digitalServiceRepository.count();
    }

    public long countByStatus(ServiceStatus status) {
        return digitalServiceRepository.countByStatus(status);
    }

    public long countCriticalServices() {
        return digitalServiceRepository.countByCriticalityLevelGreaterThanEqual(4);
    }

    public List<DigitalService> getHighRiskServices() {
        List<DigitalService> highRisk = new ArrayList<>(
                digitalServiceRepository.findByStatus(ServiceStatus.HIGH_RISK));
        highRisk.addAll(digitalServiceRepository.findByStatus(ServiceStatus.DOWN));
        return highRisk;
    }

    /** Update the health status of a service — called when risk recalculation runs */
    public DigitalService updateStatus(String serviceCode, ServiceStatus status) {
        return digitalServiceRepository.findByServiceCode(serviceCode)
                .map(svc -> {
                    svc.setStatus(status);
                    return digitalServiceRepository.save(svc);
                })
                .orElseThrow(() -> new RuntimeException("Service not found: " + serviceCode));
    }
}
