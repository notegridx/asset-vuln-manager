package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import dev.notegridx.security.assetvulnmanager.repository.AdminRunRepository;
import dev.notegridx.security.assetvulnmanager.service.AdminCveDeltaUpdateService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AdminSyncController {

	private final AdminCveDeltaUpdateService deltaUpdateService;
	private final AdminRunRepository adminRunRepository;

	public AdminSyncController(
			AdminCveDeltaUpdateService deltaUpdateService,
			AdminRunRepository adminRunRepository
	) {
		this.deltaUpdateService = deltaUpdateService;
		this.adminRunRepository = adminRunRepository;
	}

	@GetMapping("/admin/sync")
	public String view(Model model) {
		adminRunRepository
				.findTop1ByJobTypeOrderByStartedAtDescIdDesc(AdminJobType.CVE_DELTA_UPDATE)
				.ifPresent(r -> model.addAttribute("lastRun", r));

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

		// After run, show the latest job run record too.
		adminRunRepository
				.findTop1ByJobTypeOrderByStartedAtDescIdDesc(AdminJobType.CVE_DELTA_UPDATE)
				.ifPresent(r -> model.addAttribute("lastRun", r));

		return "admin/sync";
	}
}