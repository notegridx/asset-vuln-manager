package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.service.DictionaryValidationException;
import dev.notegridx.security.assetvulnmanager.service.SoftwareInstallService;
import dev.notegridx.security.assetvulnmanager.web.form.SoftwareInstallForm;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Controller
@RequiredArgsConstructor
@RequestMapping("/software")
public class SoftwareController {

    private static final DateTimeFormatter HTML_DATETIME = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm");

    private final SoftwareInstallRepository softwareInstallRepository;
    private final SoftwareInstallService softwareInstallService;

    @GetMapping("/{id}")
    public String detail(@PathVariable Long id, Model model) {
        SoftwareInstall s = softwareInstallRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("SoftwareInstall not found. id=" + id));

        model.addAttribute("software", s);
        model.addAttribute("assetId", s.getAsset().getId());
        return "software/detail";
    }

    @PreAuthorize("hasAnyRole('ADMIN','OPERATOR')")
    @PostMapping("/{id}/delete")
    public String deleteSoftware(
            @PathVariable("id") Long id,
            @RequestParam(name = "assetId", required = false) Long assetId
    ) {
        softwareInstallService.deleteCascade(id);
        if (assetId != null) {
            return "redirect:/assets/" + assetId;
        }
        return "redirect:/assets";
    }

    @PreAuthorize("hasAnyRole('ADMIN','OPERATOR')")
    @GetMapping("/{id}/edit")
    public String editForm(@PathVariable Long id, Model model) {
        SoftwareInstall s = softwareInstallRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("SoftwareInstall not found. id=" + id));

        SoftwareInstallForm form = toForm(s);
        addEditModel(model, s, form);
        return "software/edit";
    }

    @PreAuthorize("hasAnyRole('ADMIN','OPERATOR')")
    @PostMapping("/{id}/edit")
    public String update(
            @PathVariable Long id,
            @Valid @ModelAttribute("softwareInstallForm") SoftwareInstallForm form,
            BindingResult bindingResult,
            Model model
    ) {
        SoftwareInstall s = softwareInstallRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("SoftwareInstall not found. id=" + id));

        if (bindingResult.hasErrors()) {
            addEditModel(model, s, form);
            return "software/edit";
        }

        try {
            softwareInstallService.updateEditableFields(id, form);

        } catch (DictionaryValidationException e) {
            bindingResult.rejectValue(
                    e.getField(),
                    e.getCode().name(),
                    e.getMessage()
            );
            addEditModel(model, s, form);
            return "software/edit";

        } catch (IllegalArgumentException e) {
            bindingResult.reject("invalid", e.getMessage());
            addEditModel(model, s, form);
            return "software/edit";

        } catch (DataIntegrityViolationException e) {
            bindingResult.reject("duplicate", "This software is already registered for this asset.");
            addEditModel(model, s, form);
            return "software/edit";
        }

        return "redirect:/assets/" + s.getAsset().getId();
    }

    private void addEditModel(Model model, SoftwareInstall s, SoftwareInstallForm form) {
        model.addAttribute("softwareInstallForm", form);
        model.addAttribute("softwareId", s.getId());
        model.addAttribute("assetId", s.getAsset().getId());
    }

    private SoftwareInstallForm toForm(SoftwareInstall s) {
        SoftwareInstallForm form = new SoftwareInstallForm();

        form.setType(s.getType() != null ? s.getType().name() : null);
        form.setSource(s.getSource());
        form.setSourceType(s.getSourceType());

        form.setVendor(s.getVendor());
        form.setProduct(s.getProduct());
        form.setVersion(s.getVersion());
        form.setCpeName(s.getCpeName());

        form.setVendorRaw(s.getVendorRaw());
        form.setProductRaw(s.getProductRaw());
        form.setVersionRaw(s.getVersionRaw());

        form.setLastSeenAt(formatDateTime(s.getLastSeenAt()));
        form.setInstalledAt(formatDateTime(s.getInstalledAt()));

        form.setInstallLocation(s.getInstallLocation());
        form.setPackageIdentifier(s.getPackageIdentifier());
        form.setArch(s.getArch());

        form.setPublisher(s.getPublisher());
        form.setBundleId(s.getBundleId());
        form.setPackageManager(s.getPackageManager());
        form.setInstallSource(s.getInstallSource());
        form.setEdition(s.getEdition());
        form.setChannel(s.getChannel());
        form.setRelease(s.getRelease());
        form.setPurl(s.getPurl());

        return form;
    }

    private String formatDateTime(LocalDateTime value) {
        return value == null ? null : value.format(HTML_DATETIME);
    }
}