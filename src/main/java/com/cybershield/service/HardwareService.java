package com.cybershield.service;

import com.cybershield.model.AuditLog.Action;
import com.cybershield.model.AuditLog.TargetType;
import com.cybershield.model.Hardware;
import com.cybershield.repository.HardwareRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class HardwareService {

    private final HardwareRepository hardwareRepository;
    private final AuditLogService auditLogService;

    public List<Hardware> getAll() {
        return hardwareRepository.findAll();
    }

    public Hardware getById(Long id) {
        return hardwareRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Hardware not found with id: " + id));
    }

    public Hardware create(Hardware hardware, Long actorUserId, String ip) {
        if (hardwareRepository.existsByAssetTag(hardware.getAssetTag())) {
            throw new RuntimeException("Asset tag " + hardware.getAssetTag() + " already exists");
        }
        Hardware saved = hardwareRepository.save(hardware);
        auditLogService.log(actorUserId, Action.CREATE, TargetType.HARDWARE, saved.getId(), ip,
                "Created hardware: " + saved.getName() + " [" + saved.getAssetTag() + "]");
        return saved;
    }

    public Hardware update(Long id, Hardware updated, Long actorUserId, String ip) {
        Hardware existing = getById(id);
        existing.setAssetTag(updated.getAssetTag());
        existing.setName(updated.getName());
        existing.setHardwareType(updated.getHardwareType());
        existing.setManufacturer(updated.getManufacturer());
        existing.setModel(updated.getModel());
        existing.setSerialNumber(updated.getSerialNumber());
        existing.setLocation(updated.getLocation());
        existing.setStatus(updated.getStatus());
        existing.setPurchaseDate(updated.getPurchaseDate());
        existing.setWarrantyExpiry(updated.getWarrantyExpiry());
        existing.setLastMaintenanceDate(updated.getLastMaintenanceDate());
        existing.setNextMaintenanceDate(updated.getNextMaintenanceDate());
        existing.setNotes(updated.getNotes());
        Hardware saved = hardwareRepository.save(existing);
        auditLogService.log(actorUserId, Action.UPDATE, TargetType.HARDWARE, id, ip,
                "Updated hardware: " + saved.getName());
        return saved;
    }

    public void delete(Long id, Long actorUserId, String ip) {
        Hardware hw = getById(id);
        hardwareRepository.deleteById(id);
        auditLogService.log(actorUserId, Action.DELETE, TargetType.HARDWARE, id, ip,
                "Deleted hardware: " + hw.getName());
    }

    public long countTotal() { return hardwareRepository.count(); }
}
