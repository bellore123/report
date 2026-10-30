package com.cybershield.service;

import com.cybershield.model.Institution;
import com.cybershield.model.Institution.InstitutionStatus;
import com.cybershield.repository.InstitutionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

/**
 * InstitutionService provides read and status-summary access for NEDI
 * institutions represented in the demo database.
 */
@Service
@RequiredArgsConstructor
public class InstitutionService {

    private final InstitutionRepository institutionRepository;

    public List<Institution> getAll() {
        return institutionRepository.findAll();
    }

    public long countTotal() {
        return institutionRepository.count();
    }

    public long countByStatus(InstitutionStatus status) {
        return institutionRepository.countByStatus(status);
    }

    public Optional<Institution> findByCode(String institutionCode) {
        return institutionRepository.findByInstitutionCode(institutionCode);
    }

    public List<Institution> getAtRiskInstitutions() {
        List<Institution> risky = institutionRepository.findByStatus(InstitutionStatus.HIGH_RISK);
        risky.addAll(institutionRepository.findByStatus(InstitutionStatus.DEGRADED));
        risky.addAll(institutionRepository.findByStatus(InstitutionStatus.OFFLINE));
        return risky;
    }
}
