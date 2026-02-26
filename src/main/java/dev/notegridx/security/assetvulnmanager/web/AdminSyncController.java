package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.service.AdminCveDeltaUpdateService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AdminSyncController {

	private final AdminCveDeltaUpdateService deltaUpdateService;

	public AdminSyncController(AdminCveDeltaUpdateService deltaUpdateService) {
		this.deltaUpdateService = deltaUpdateService;
	}

	@GetMapping("/admin/sync")
	public String view() {
		return "admin/sync";
	}

	@PostMapping("/admin/sync")
	public String run(
			@RequestParam(name = "daysBack", defaultValue = "1") int daysBack,
			@RequestParam(name = "maxResults", defaultValue = "200") int maxResults,
			Model model
	) {
		var result = deltaUpdateService.runDeltaUpdate(daysBack, maxResults);

		model.addAttribute("daysBack", daysBack);
		model.addAttribute("maxResults", maxResults);
		model.addAttribute("result", result);

		return "admin/sync";
	}
}