package dev.notegridx.security.assetvulnmanager.web;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import dev.notegridx.security.assetvulnmanager.service.AdminSyncService;

@Controller
public class AdminSyncController {
	
	private final AdminSyncService adminSyncService;
	
	public AdminSyncController(AdminSyncService adminSyncService) {
		this.adminSyncService = adminSyncService;
	}
	
	@GetMapping("/admin/sync")
	public String view() {
		return "admin/sync";
	}
	
	@PostMapping("/admin/sync")
	public String run(
			@RequestParam(name = "daysBack", defaultValue = "7") int daysBack,
			@RequestParam(name = "maxResults", defaultValue = "200") int maxResults,
			Model model) {
		AdminSyncService.SyncResult result = adminSyncService.runSync(daysBack, maxResults);
		model.addAttribute("result", result);
		model.addAttribute("daysBack", daysBack);
		model.addAttribute("maxResults", maxResults);
		return "admin/sync";
	}

}
