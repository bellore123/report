package com.cybershield.repository;

import com.cybershield.model.Hardware;
import com.cybershield.model.Hardware.HardwareStatus;
import com.cybershield.model.Hardware.HardwareType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface HardwareRepository extends JpaRepository<Hardware, Long> {

    List<Hardware> findByHardwareType(HardwareType type);

    List<Hardware> findByStatus(HardwareStatus status);

    boolean existsByAssetTag(String assetTag);

    boolean existsBySerialNumber(String serialNumber);
}
