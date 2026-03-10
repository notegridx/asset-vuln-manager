package dev.notegridx.security.assetvulnmanager.web;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.notegridx.security.assetvulnmanager.domain.AdminRun;
import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import dev.notegridx.security.assetvulnmanager.repository.AdminRunRepository;
import dev.notegridx.security.assetvulnmanager.service.AdminCveDeltaUpdateService;
import dev.notegridx.security.assetvulnmanager.service.AdminJobAlreadyRunningException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

@Controller
public class AdminSyncController {

	private final AdminCveDeltaUpdateService deltaUpdateService;
	private final AdminRunRepository adminRunRepository;
	private final ObjectMapper objectMapper;

	public AdminSyncController(
			AdminCveDeltaUpdateService deltaUpdateService,
			AdminRunRepository adminRunRepository,
			ObjectMapper objectMapper
	) {
		this.deltaUpdateService = deltaUpdateService;
		this.adminRunRepository = adminRunRepository;
		this.objectMapper = objectMapper;
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
		Optional<AdminRun> opt = adminRunRepository
				.findTop1ByJobTypeOrderByStartedAtDescIdDesc(AdminJobType.CVE_DELTA_UPDATE);

		if (opt.isEmpty()) {
			model.addAttribute("lastRun", null);
			model.addAttribute("lastParams", null);
			model.addAttribute("lastResult", null);
			return;
		}

		AdminRun r = opt.get();
		model.addAttribute("lastRun", r);
		model.addAttribute("lastParams", parseJsonToMap(r.getParamsJson()));
		model.addAttribute("lastResult", parseJsonToMap(r.getResultJson()));
	}

	private Map<String, Object> parseJsonToMap(String json) {
		if (json == null || json.isBlank()) return null;
		try {
			return objectMapper.readValue(
					json,
					new TypeReference<LinkedHashMap<String, Object>>() {
					}
			);
		} catch (Exception e) {
			Map<String, Object> m = new LinkedHashMap<>();
			m.put("_parseError", e.getClass().getSimpleName());
			return m;
		}
	}
}