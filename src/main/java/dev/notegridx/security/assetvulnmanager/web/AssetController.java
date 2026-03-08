package dev.notegridx.security.assetvulnmanager.web;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.persistence.EntityNotFoundException;
import jakarta.validation.Valid;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.AlertRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.service.AssetService;
import dev.notegridx.security.assetvulnmanager.service.DictionaryValidationException;
import dev.notegridx.security.assetvulnmanager.service.SoftwareInstallService;
import dev.notegridx.security.assetvulnmanager.web.form.AssetForm;
import dev.notegridx.security.assetvulnmanager.web.form.SoftwareInstallForm;

@Controller
public class AssetController {

    private final AssetService assetService;
    private final SoftwareInstallService softwareInstallService;
    private final AlertRepository alertRepository;
    private final CpeVendorRepository cpeVendorRepository;
    private final CpeProductRepository cpeProductRepository;

    public AssetController(
            AssetService assetService,
            SoftwareInstallService softwareInstallService,
            AlertRepository alertRepository,
            CpeVendorRepository cpeVendorRepository,
            CpeProductRepository cpeProductRepository
    ) {
        this.assetService = assetService;
        this.softwareInstallService = softwareInstallService;
        this.alertRepository = alertRepository;
        this.cpeVendorRepository = cpeVendorRepository;
        this.cpeProductRepository = cpeProductRepository;
    }

    @PostMapping("/assets/{id}/delete")
    public String deleteAsset(@PathVariable("id") Long id) {
        assetService.deleteCascade(id);
        return "redirect:/assets";
    }

    @GetMapping("/assets")
    public String list(Model model) {
        List<Asset> assets = assetService.findAll();
        model.addAttribute("assets", assets);
        return "assets/list";
    }

    @GetMapping("/assets/new")
    public String newForm(Model model) {
        model.addAttribute("assetForm", new AssetForm());
        return "assets/new";
    }

    @PostMapping("/assets")
    public String create(
            @Valid @ModelAttribute("assetForm") AssetForm form,
            BindingResult bindingResult
    ) {
        if (bindingResult.hasErrors()) {
            return "assets/new";
        }

        try {
            assetService.create(
                    form.getExternalKey(),
                    form.getName(),
                    form.getAssetType(),
                    form.getOwner(),
                    form.getNote()
            );
        } catch (DataIntegrityViolationException e) {
            bindingResult.rejectValue("externalKey", "duplicate", "External Key is already used.");
            return "assets/new";
        }

        return "redirect:/assets";
    }

    @GetMapping("/assets/{assetId}")
    public String detail(@PathVariable Long assetId, Model model) {
        Asset asset = assetService.getRequired(assetId);
        List<SoftwareInstall> installs = softwareInstallService.findByAssetId(assetId);

        Map<Long, Long> alertCountBySoftwareId = new HashMap<>();
        if (!installs.isEmpty()) {
            List<Long> softwareIds = installs.stream()
                    .map(SoftwareInstall::getId)
                    .toList();

            for (Object[] row : alertRepository.countBySoftwareInstallIds(softwareIds)) {
                Long softwareId = ((Number) row[0]).longValue();
                Long count = ((Number) row[1]).longValue();
                alertCountBySoftwareId.put(softwareId, count);
            }
        }

        Set<Long> vendorIds = new HashSet<>();
        Set<Long> productIds = new HashSet<>();
        for (SoftwareInstall s : installs) {
            if (s.getCpeVendorId() != null) {
                vendorIds.add(s.getCpeVendorId());
            }
            if (s.getCpeProductId() != null) {
                productIds.add(s.getCpeProductId());
            }
        }

        Map<Long, String> vendorNameMap = new HashMap<>();
        for (CpeVendor v : cpeVendorRepository.findAllById(vendorIds)) {
            vendorNameMap.put(v.getId(), firstNonBlank(v.getDisplayName(), v.getNameNorm(), "#" + v.getId()));
        }

        Map<Long, String> productNameMap = new HashMap<>();
        for (CpeProduct p : cpeProductRepository.findAllById(productIds)) {
            productNameMap.put(p.getId(), firstNonBlank(p.getDisplayName(), p.getNameNorm(), "#" + p.getId()));
        }

        model.addAttribute("asset", asset);
        model.addAttribute("installs", installs);
        model.addAttribute("alertCountBySoftwareId", alertCountBySoftwareId);
        model.addAttribute("vendorNameMap", vendorNameMap);
        model.addAttribute("productNameMap", productNameMap);
        return "assets/detail";
    }

    @GetMapping("/assets/{assetId}/software/new")
    public String newSoftware(@PathVariable Long assetId, Model model) {
        Asset asset = assetService.getRequired(assetId);

        model.addAttribute("asset", asset);
        model.addAttribute("softwareInstallForm", new SoftwareInstallForm());
        return "assets/software_new";
    }

    @PostMapping("/assets/{assetId}/software")
    public String createSoftware(
            @PathVariable Long assetId,
            @Valid @ModelAttribute("softwareInstallForm") SoftwareInstallForm form,
            BindingResult bindingResult,
            Model model
    ) {
        Asset asset = assetService.getRequired(assetId);

        if (bindingResult.hasErrors()) {
            model.addAttribute("asset", asset);
            return "assets/software_new";
        }

        try {
            softwareInstallService.addToAsset(
                    asset,
                    form.getVendor(),
                    form.getProduct(),
                    form.getVersion(),
                    form.getCpeName()
            );

        } catch (DictionaryValidationException e) {
            bindingResult.rejectValue(
                    e.getField(),
                    e.getCode().name(),
                    e.getMessage()
            );
            model.addAttribute("asset", asset);
            return "assets/software_new";

        } catch (DataIntegrityViolationException e) {
            bindingResult.reject("duplicate", "This software is already registered for this asset");
            model.addAttribute("asset", asset);
            return "assets/software_new";
        }

        return "redirect:/assets/" + assetId;
    }

    @GetMapping("/assets/{id}/edit")
    public String editAsset(@PathVariable Long id, Model model) {
        Asset asset = assetService.getRequired(id);

        AssetForm form = new AssetForm();
        form.setExternalKey(asset.getExternalKey());
        form.setName(asset.getName());
        form.setAssetType(asset.getAssetType());
        form.setOwner(asset.getOwner());
        form.setNote(asset.getNote());
        form.setSource(asset.getSource());
        form.setPlatform(asset.getPlatform());
        form.setOsVersion(asset.getOsVersion());

        model.addAttribute("asset", asset);
        model.addAttribute("assetForm", form);
        return "assets/edit";
    }

    @PostMapping("/assets/{id}/edit")
    public String updateAsset(@PathVariable Long id,
                              @Valid @ModelAttribute("assetForm") AssetForm form,
                              BindingResult binding,
                              Model model) {

        if (binding.hasErrors()) {
            model.addAttribute("asset", assetService.getRequired(id));
            return "assets/edit";
        }

        try {
            assetService.update(
                    id,
                    form.getExternalKey(),
                    form.getName(),
                    form.getAssetType(),
                    form.getOwner(),
                    form.getNote(),
                    form.getSource(),
                    form.getPlatform(),
                    form.getOsVersion()
            );
        } catch (DataIntegrityViolationException e) {
            binding.rejectValue("externalKey", "duplicate", "External Key is already used.");
            model.addAttribute("asset", assetService.getRequired(id));
            return "assets/edit";
        } catch (IllegalArgumentException e) {
            binding.reject("invalid", e.getMessage());
            model.addAttribute("asset", assetService.getRequired(id));
            return "assets/edit";
        }

        return "redirect:/assets/" + id;
    }

    @ExceptionHandler(EntityNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public String notFound(EntityNotFoundException ex, Model model) {
        model.addAttribute("message", ex.getMessage());
        return "error/404";
    }

    private static String firstNonBlank(String a, String b, String fallback) {
        if (a != null && !a.isBlank()) return a;
        if (b != null && !b.isBlank()) return b;
        return fallback;
    }
}