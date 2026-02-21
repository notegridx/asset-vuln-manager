package dev.notegridx.security.assetvulnmanager.web;

import java.util.*;
import java.util.stream.Collectors;

import dev.notegridx.security.assetvulnmanager.domain.Alert;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertStatus;
import dev.notegridx.security.assetvulnmanager.domain.enums.CloseReason;
import dev.notegridx.security.assetvulnmanager.domain.enums.Severity;
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

	/**
	 * 既存: /alerts?status=...
	 * 追加: /alerts?status=...&assetId=...
	 */
	@GetMapping("/alerts")
	public String list(
			@RequestParam(name = "status", required = false) String status,
			@RequestParam(name = "assetId", required = false) Long assetId,
			Model model
	) {

		String effective = (status != null) ? status.toUpperCase(Locale.ROOT) : "OPEN";

		List<Alert> alerts;

		switch (effective) {
			case "CLOSED" -> {
				if (assetId != null) alerts = alertService.findByAssetId(assetId, AlertStatus.CLOSED);
				else alerts = alertService.findByStatus(AlertStatus.CLOSED);
			}
			case "ALL" -> {
				if (assetId != null) alerts = alertService.findByAssetId(assetId, null);
				else alerts = alertService.findAll();
			}
			default -> {
				effective = "OPEN";
				if (assetId != null) alerts = alertService.findByAssetId(assetId, AlertStatus.OPEN);
				else alerts = alertService.findByStatus(AlertStatus.OPEN);
			}
		}

		model.addAttribute("alerts", alerts);
		model.addAttribute("status", effective);
		model.addAttribute("assetId", assetId); // drilldown時に表示に使える

		return "alerts/list";
	}

	/**
	 * Option C Step1: Asset集約ビュー
	 * /alerts/by-asset?status=OPEN|CLOSED|ALL
	 */
	@GetMapping("/alerts/by-asset")
	public String byAsset(
			@RequestParam(name = "status", required = false) String status,
			Model model
	) {
		String effective = (status != null) ? status.toUpperCase(Locale.ROOT) : "OPEN";

		List<Alert> alerts = switch (effective) {
			case "CLOSED" -> alertService.findByStatus(AlertStatus.CLOSED);
			case "ALL" -> alertService.findAll();
			default -> {
				effective = "OPEN";
				yield alertService.findByStatus(AlertStatus.OPEN);
			}
		};

		// assetId -> rows
		Map<Long, List<Alert>> byAssetId = new LinkedHashMap<>();
		for (Alert a : alerts) {
			Long aid = a.getSoftwareInstall().getAsset().getId();
			byAssetId.computeIfAbsent(aid, k -> new ArrayList<>()).add(a);
		}

		List<AssetAggRow> rows = new ArrayList<>();
		for (var e : byAssetId.entrySet()) {
			Long assetId = e.getKey();
			List<Alert> list = e.getValue();

			String assetName = list.get(0).getSoftwareInstall().getAsset().getName();
			int total = list.size();

			int critical = 0, high = 0, medium = 0, low = 0, none = 0;
			for (Alert a : list) {
				Severity sev = a.getVulnerability().getSeverity();
				if (sev == null) { none++; continue; }
				switch (sev) {
					case CRITICAL -> critical++;
					case HIGH -> high++;
					case MEDIUM -> medium++;
					case LOW -> low++;
					default -> none++;
				}
			}

			// “最も強いSeverity” を表示用に決める
			Severity top = null;
			if (critical > 0) top = Severity.CRITICAL;
			else if (high > 0) top = Severity.HIGH;
			else if (medium > 0) top = Severity.MEDIUM;
			else if (low > 0) top = Severity.LOW;

			// lastSeen 最新
			var lastSeen = list.stream()
					.map(Alert::getLastSeenAt)
					.filter(Objects::nonNull)
					.max(Comparator.naturalOrder())
					.orElse(null);

			// software件数（installId distinct）
			long softwareCount = list.stream()
					.map(a -> a.getSoftwareInstall().getId())
					.distinct()
					.count();

			rows.add(new AssetAggRow(
					assetId,
					assetName,
					(int) softwareCount,
					total,
					top,
					critical, high, medium, low, none,
					lastSeen
			));
		}

		// 並び: topSeverity desc → total desc → assetId desc
		rows = rows.stream()
				.sorted((a, b) -> {
					int s = Integer.compare(sevRank(b.topSeverity), sevRank(a.topSeverity));
					if (s != 0) return s;
					int t = Integer.compare(b.totalAlerts, a.totalAlerts);
					if (t != 0) return t;
					return Long.compare(b.assetId, a.assetId);
				})
				.collect(Collectors.toList());

		model.addAttribute("rows", rows);
		model.addAttribute("status", effective);

		return "alerts/by_asset";
	}

	private static int sevRank(Severity s) {
		if (s == null) return 0;
		return switch (s) {
			case CRITICAL -> 4;
			case HIGH -> 3;
			case MEDIUM -> 2;
			case LOW -> 1;
			default -> 0;
		};
	}

	public record AssetAggRow(
			Long assetId,
			String assetName,
			int softwareCount,
			int totalAlerts,
			Severity topSeverity,
			int critical,
			int high,
			int medium,
			int low,
			int none,
			Object lastSeenAt // LocalDateTime想定（テンプレでそのまま出す）
	) {}

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