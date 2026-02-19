package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.service.DictionaryValidationException;
import dev.notegridx.security.assetvulnmanager.service.SoftwareInstallService;
import dev.notegridx.security.assetvulnmanager.web.form.SoftwareInstallForm;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

@Controller
@RequiredArgsConstructor
@RequestMapping("/software")
public class SoftwareController {

	private final SoftwareInstallRepository softwareInstallRepository;
	private final SoftwareInstallService softwareInstallService;

	@GetMapping("/{id}/edit")
	public String editForm(@PathVariable Long id, Model model) {
		SoftwareInstall s = softwareInstallRepository.findById(id)
				.orElseThrow(() -> new IllegalArgumentException("SoftwareInstall not found. id=" + id));

		SoftwareInstallForm form = new SoftwareInstallForm();
		form.setVendor(s.getVendor());
		form.setProduct(s.getProduct());
		form.setVersion(s.getVersion());
		form.setCpeName(s.getCpeName());

		model.addAttribute("softwareInstallForm", form);
		model.addAttribute("softwareId", s.getId());
		model.addAttribute("assetId", s.getAsset().getId());

		return "software/edit";
	}

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
			model.addAttribute("softwareId", s.getId());
			model.addAttribute("assetId", s.getAsset().getId());
			return "software/edit";
		}

		try {
			softwareInstallService.updateDetails(
					id,
					form.getVendor(),
					form.getProduct(),
					form.getVersion(),
					form.getCpeName()
			);

		} catch (DictionaryValidationException e) {
			// vendor / product のどちらで落ちてもフォームに表示できる
			bindingResult.rejectValue(
					e.getField(),
					e.getCode().name(),
					e.getMessage()
			);
			model.addAttribute("softwareId", s.getId());
			model.addAttribute("assetId", s.getAsset().getId());
			return "software/edit";

		} catch (DataIntegrityViolationException e) {
			bindingResult.reject("duplicate", "This software is already registered for this asset.");
			model.addAttribute("softwareId", s.getId());
			model.addAttribute("assetId", s.getAsset().getId());
			return "software/edit";
		}

		return "redirect:/assets/" + s.getAsset().getId();
	}
}
