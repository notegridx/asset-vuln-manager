package dev.notegridx.security.assetvulnmanager.web;

import java.util.List;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import dev.notegridx.security.assetvulnmanager.domain.Alert;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertStatus;
import dev.notegridx.security.assetvulnmanager.repository.AlertRepository;

@Controller
public class AlertController {
	
	private final AlertRepository alertRepository;
	
	public AlertController(AlertRepository alertRepository) {
		this.alertRepository = alertRepository;
	}
	
	@GetMapping("/alerts")
	public String list(Model model) {
		List<Alert> alerts = alertRepository.findByStatusOrderByLastSeenAtDesc(AlertStatus.OPEN);
		model.addAttribute("alerts", alerts);
		return "alerts/list";
	}

}
