package dev.notegridx.security.assetvulnmanager.web;

import java.util.List;

import jakarta.persistence.EntityNotFoundException;
import jakarta.validation.Valid;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.service.AssetService;
import dev.notegridx.security.assetvulnmanager.service.DictionaryValidationException;
import dev.notegridx.security.assetvulnmanager.service.SoftwareInstallService;
import dev.notegridx.security.assetvulnmanager.web.form.AssetForm;
import dev.notegridx.security.assetvulnmanager.web.form.SoftwareInstallForm;

@Controller
public class AssetController {

    private final AssetService assetService;
    private final SoftwareInstallService softwareInstallService;

    public AssetController(
            AssetService assetService,
            SoftwareInstallService softwareInstallService
    ) {
        this.assetService = assetService;
        this.softwareInstallService = softwareInstallService;
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

        model.addAttribute("asset", asset);
        model.addAttribute("installs", installs);
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
            // vendor/product どちらで落ちてもフォームに表示できる
            // e.getField() は "vendor" or "product" を想定
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
            // external_key UNIQUE など想定
            binding.rejectValue("externalKey", "duplicate", "External Key is already used.");
            model.addAttribute("asset", assetService.getRequired(id));
            return "assets/edit";
        } catch (IllegalArgumentException e) {
            // updateName/updateDetails のバリデーションなど
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
        return "errors/404";
    }
}
