package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.domain.enums.SoftwareType;
import dev.notegridx.security.assetvulnmanager.repository.AlertRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.web.form.SoftwareInstallForm;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.time.format.DateTimeParseException;
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
    public SoftwareInstall addToAsset(Asset asset, SoftwareInstallForm form) {
        if (asset == null) {
            throw new IllegalArgumentException("asset is required");
        }

        SoftwareDictionaryValidator.Resolve r;
        if (dictMode == DictMode.STRICT) {
            r = dictValidator.resolveOrThrow(form.getVendor(), form.getProduct());
        } else {
            r = dictValidator.resolve(form.getVendor(), form.getProduct());
        }

        SoftwareInstall si = new SoftwareInstall(asset, form.getProduct());

        si.updateDetails(
                form.getVendor(),
                form.getProduct(),
                form.getVersion(),
                form.getCpeName()
        );

        si.setType(parseSoftwareType(form.getType()));
        si.setSource(form.getSource());

        si.captureRaw(
                form.getVendorRaw(),
                form.getProductRaw(),
                form.getVersionRaw()
        );

        si.updateImportExtended(
                form.getInstallLocation(),
                parseLocalDateTime(form.getInstalledAt()),
                form.getPackageIdentifier(),
                form.getArch(),
                form.getSourceType(),
                parseLocalDateTime(form.getLastSeenAt()),
                form.getPublisher(),
                form.getBundleId(),
                form.getPackageManager(),
                form.getInstallSource(),
                form.getEdition(),
                form.getChannel(),
                form.getRelease(),
                form.getPurl()
        );

        if (r.hit()) {
            si.linkCanonical(r.vendorId(), r.productId());
        } else if (r.vendorId() != null) {
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
            si.linkCanonical(r.vendorId(), null);
        } else {
            si.unlinkCanonical();
        }

        return softwareInstallRepository.save(si);
    }

    @Transactional
    public SoftwareInstall updateEditableFields(Long softwareInstallId, SoftwareInstallForm form) {
        SoftwareDictionaryValidator.Resolve r;
        if (dictMode == DictMode.STRICT) {
            r = dictValidator.resolveOrThrow(form.getVendor(), form.getProduct());
        } else {
            r = dictValidator.resolve(form.getVendor(), form.getProduct());
        }

        SoftwareInstall si = getRequired(softwareInstallId);

        si.updateDetails(
                form.getVendor(),
                form.getProduct(),
                form.getVersion(),
                form.getCpeName()
        );

        si.setType(parseSoftwareType(form.getType()));
        si.setSource(form.getSource());

        si.captureRaw(
                form.getVendorRaw(),
                form.getProductRaw(),
                form.getVersionRaw()
        );

        si.updateImportExtended(
                form.getInstallLocation(),
                parseLocalDateTime(form.getInstalledAt()),
                form.getPackageIdentifier(),
                form.getArch(),
                form.getSourceType(),
                parseLocalDateTime(form.getLastSeenAt()),
                form.getPublisher(),
                form.getBundleId(),
                form.getPackageManager(),
                form.getInstallSource(),
                form.getEdition(),
                form.getChannel(),
                form.getRelease(),
                form.getPurl()
        );

        if (r.hit()) {
            si.linkCanonical(r.vendorId(), r.productId());
        } else if (r.vendorId() != null) {
            si.linkCanonical(r.vendorId(), null);
        } else {
            si.unlinkCanonical();
        }

        return softwareInstallRepository.save(si);
    }

    private static SoftwareType parseSoftwareType(String value) {
        if (value == null || value.isBlank()) {
            return SoftwareType.APPLICATION;
        }
        try {
            return SoftwareType.valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            return SoftwareType.APPLICATION;
        }
    }

    private static LocalDateTime parseLocalDateTime(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return LocalDateTime.parse(value.trim());
        } catch (DateTimeParseException ex) {
            throw new IllegalArgumentException("Invalid datetime format: " + value, ex);
        }
    }
}