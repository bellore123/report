package com.cybershield.repository;

import com.cybershield.model.Institution;
import com.cybershield.model.Institution.InstitutionStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface InstitutionRepository extends JpaRepository<Institution, Long> {
    Optional<Institution> findByInstitutionCode(String institutionCode);
    List<Institution> findByStatus(InstitutionStatus status);
    long countByStatus(InstitutionStatus status);
}
