package dev.notegridx.security.assetvulnmanager.web;

import jakarta.validation.Valid;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.service.SoftwareInstallService;
import dev.notegridx.security.assetvulnmanager.web.form.SoftwareInstallForm;
import lombok.RequiredArgsConstructor;

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
	public String update(@PathVariable Long id,
			@Valid @ModelAttribute("softwareInstallForm") SoftwareInstallForm form,
	BindingResult bindingResult,
	Model model) {
		SoftwareInstall s = softwareInstallRepository.findById(id)
				.orElseThrow(() -> new IllegalArgumentException("SoftwareInstall not found. id=" + id));
		
		if (bindingResult.hasErrors()) {
			model.addAttribute("softwareId", s.getId());
			model.addAttribute("assetId", s.getAsset().getId());
			return "software/edit";
		}
		
		softwareInstallService.updateDetails(id, form.getVendor(), form.getProduct(), form.getVersion(), form.getCpeName());
		
		return "redirect:/assets/" + s.getAsset().getId();
	}

}
