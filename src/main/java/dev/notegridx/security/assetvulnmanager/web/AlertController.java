package dev.notegridx.security.assetvulnmanager.web;

import java.util.List;

import dev.notegridx.security.assetvulnmanager.domain.Alert;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertStatus;
import dev.notegridx.security.assetvulnmanager.domain.enums.CloseReason;
import dev.notegridx.security.assetvulnmanager.service.AlertService;
import dev.notegridx.security.assetvulnmanager.web.form.AlertCloseForm;
import jakarta.persistence.EntityNotFoundException;
import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@Controller
public class AlertController {

	private final AlertService alertService;

	public AlertController(AlertService alertService) {
		this.alertService = alertService;
	}

	@GetMapping("/alerts")
	public String list(
			@RequestParam(name = "status", required = false) String status,
			Model model
	) {

		String effective = (status != null) ? status.toUpperCase() : "OPEN";

		List<Alert> alerts;

		switch (effective) {
			case "CLOSED" -> alerts = alertService.findByStatus(AlertStatus.CLOSED);
			case "ALL" -> alerts = alertService.findAll();
			default -> {
				effective = "OPEN";
				alerts = alertService.findByStatus(AlertStatus.OPEN);
			}
		}

		model.addAttribute("alerts", alerts);
		model.addAttribute("status", effective);

		return "alerts/list";
	}

	@GetMapping("/alerts/{id}")
	public String detail(@PathVariable Long id, Model model) {
		Alert alert;
		try {
			alert = alertService.getRequired(id);
		} catch (EntityNotFoundException e) {
			throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Alert not found: " + id);
		}

		model.addAttribute("alert", alert);
		model.addAttribute("closeForm", new AlertCloseForm());
		model.addAttribute("closeReasons", CloseReason.values());
		return "alerts/detail";
	}

	@PostMapping("/alerts/{id}/close")
	public String close(
			@PathVariable Long id,
			@Valid @ModelAttribute("closeForm") AlertCloseForm closeForm,
			BindingResult bindingResult,
			Model model
	) {
		Alert alert = alertService.getRequired(id);

		if (bindingResult.hasErrors()) {
			model.addAttribute("alert", alert);
			model.addAttribute("closeReasons", CloseReason.values());
			return "alerts/detail";
		}

		alertService.close(id, closeForm.getCloseReason());
		return "redirect:/alerts/" + id;
	}
}
