package dev.notegridx.security.assetvulnmanager.web;

import java.util.List;

import jakarta.persistence.EntityNotFoundException;
import jakarta.validation.Valid;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseStatus;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.service.AssetService;
import dev.notegridx.security.assetvulnmanager.service.SoftwareInstallService;
import dev.notegridx.security.assetvulnmanager.web.form.AssetForm;
import dev.notegridx.security.assetvulnmanager.web.form.SoftwareInstallForm;

@Controller
public class AssetController {
	
	private final AssetService assetService;
	private final SoftwareInstallService softwareInstallService;
	
	public AssetController(AssetService assetService,
			SoftwareInstallService softwareInstallService) {
		this.assetService = assetService;
		this.softwareInstallService = softwareInstallService;
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
		
		assetService.create(form.getName(), form.getAssetType(), form.getOwner(), form.getNote());
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
		
		softwareInstallService.addToAsset(asset, form.getVendor(), form.getProduct(), form.getVersion(), form.getCpeName());
		return "redirect:/assets/" + assetId;
	}
	
	@ExceptionHandler(EntityNotFoundException.class)
	@ResponseStatus(org.springframework.http.HttpStatus.NOT_FOUND)
	public String notFound(EntityNotFoundException ex, Model model) {
		model.addAttribute("message", ex.getMessage());
		return "errors/404";
	}

}
