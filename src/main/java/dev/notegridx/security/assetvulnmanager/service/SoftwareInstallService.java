package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.AlertRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Locale;

@Service
public class SoftwareInstallService {

    public enum DictMode {STRICT, LENIENT}

    private final SoftwareInstallRepository softwareInstallRepository;
    private final AlertRepository alertRepository;
    private final SoftwareDictionaryValidator dictValidator;
    private final DictMode dictMode;

    public SoftwareInstallService(
            SoftwareInstallRepository softwareInstallRepository,
            AlertRepository alertRepository,
            SoftwareDictionaryValidator dictValidator,
            @Value("${app.software.dict-mode:LENIENT}") String dictMode
    ) {
        this.softwareInstallRepository = softwareInstallRepository;
        this.alertRepository = alertRepository;
        this.dictValidator = dictValidator;
        this.dictMode = parseDictMode(dictMode);
    }

    @Transactional
    public void deleteCascade(Long installId) {
        alertRepository.deleteBySoftwareInstallId(installId);
        softwareInstallRepository.deleteById(installId);
    }

    private static DictMode parseDictMode(String s) {
        if (s == null) return DictMode.LENIENT;
        try {
            return DictMode.valueOf(s.trim().toUpperCase(Locale.ROOT));
        } catch (Exception e) {
            return DictMode.LENIENT;
        }
    }

    @Transactional(readOnly = true)
    public List<SoftwareInstall> findByAssetId(Long assetId) {
        return softwareInstallRepository.findByAssetIdOrderByIdDesc(assetId);
    }

    @Transactional(readOnly = true)
    public SoftwareInstall getRequired(Long id) {
        return softwareInstallRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("SoftwareInstall not found. id=" + id));
    }

    @Transactional
    public SoftwareInstall addToAsset(
            Asset asset,
            String vendor,
            String product,
            String version,
            String cpeName
    ) {
        SoftwareDictionaryValidator.Resolve r;
        if (dictMode == DictMode.STRICT) {
            r = dictValidator.resolveOrThrow(vendor, product);
        } else {
            r = dictValidator.resolve(vendor, product);
        }

        SoftwareInstall si = new SoftwareInstall(asset, product);
        si.updateDetails(vendor, product, version, cpeName);

        if (r.hit()) {
            si.linkCanonical(r.vendorId(), r.productId());
        } else if (r.vendorId() != null) {
            // ✅ vendor は確定しているので vendor-only を保持
            si.linkCanonical(r.vendorId(), null);
        } else {
            si.unlinkCanonical();
        }

        return softwareInstallRepository.save(si);
    }

    @Transactional
    public SoftwareInstall updateDetails(
            Long softwareInstallId,
            String vendor,
            String product,
            String version,
            String cpeName
    ) {
        SoftwareDictionaryValidator.Resolve r;
        if (dictMode == DictMode.STRICT) {
            r = dictValidator.resolveOrThrow(vendor, product);
        } else {
            r = dictValidator.resolve(vendor, product);
        }

        SoftwareInstall si = getRequired(softwareInstallId);
        si.updateDetails(vendor, product, version, cpeName);

        if (r.hit()) {
            si.linkCanonical(r.vendorId(), r.productId());
        } else if (r.vendorId() != null) {
            // ✅ 入力が変わって product が外れても vendor が確定していれば vendor-only に落とす
            // （古い product link の残留は防ぎつつ vendor は保持）
            si.linkCanonical(r.vendorId(), null);
        } else {
            si.unlinkCanonical();
        }

        return softwareInstallRepository.save(si);
    }
}