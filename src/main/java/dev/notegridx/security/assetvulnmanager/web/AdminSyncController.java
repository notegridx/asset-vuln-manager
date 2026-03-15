package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import dev.notegridx.security.assetvulnmanager.service.AdminCveDeltaUpdateService;
import dev.notegridx.security.assetvulnmanager.service.AdminJobAlreadyRunningException;
import dev.notegridx.security.assetvulnmanager.service.AdminRunReadService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AdminSyncController {

	private final AdminCveDeltaUpdateService deltaUpdateService;
	private final AdminRunReadService adminRunReadService;

	public AdminSyncController(
			AdminCveDeltaUpdateService deltaUpdateService,
			AdminRunReadService adminRunReadService
	) {
		this.deltaUpdateService = deltaUpdateService;
		this.adminRunReadService = adminRunReadService;
	}

	@GetMapping("/admin/sync")
	public String view(Model model) {
		loadLastRun(model);
		return "admin/sync";
	}

	@PostMapping("/admin/sync")
	public String run(
			@RequestParam(name = "daysBack", defaultValue = "1") int daysBack,
			@RequestParam(name = "maxResults", defaultValue = "200") int maxResults,
			Model model
	) {
		try {
			var result = deltaUpdateService.runDeltaUpdate(daysBack, maxResults);
			model.addAttribute("result", result);
		} catch (AdminJobAlreadyRunningException ex) {
			model.addAttribute("error", ex.getMessage());
		}

		model.addAttribute("daysBack", daysBack);
		model.addAttribute("maxResults", maxResults);

		loadLastRun(model);
		return "admin/sync";
	}

	private void loadLastRun(Model model) {
		AdminRunReadService.LastRunView last = adminRunReadService.findLastRun(
				AdminJobType.CVE_DELTA_UPDATE,
				AdminRunReadService.ParseErrorStyle.SIMPLE_CLASS_NAME
		);

		if (last == null) {
			model.addAttribute("lastRun", null);
			model.addAttribute("lastParams", null);
			model.addAttribute("lastResult", null);
			return;
		}

		model.addAttribute("lastRun", last.run());
		model.addAttribute("lastParams", last.params());
		model.addAttribute("lastResult", last.result());
	}
}