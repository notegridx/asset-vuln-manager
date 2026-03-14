package dev.notegridx.security.assetvulnmanager.web;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

import dev.notegridx.security.assetvulnmanager.domain.Alert;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertCertainty;
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

	private static final Set<String> ALLOWED_CERTAINTY = Set.of("ALL", "CONFIRMED", "UNCONFIRMED");

	private final AlertService alertService;

	public AlertController(AlertService alertService) {
		this.alertService = alertService;
	}

	@GetMapping("/alerts")
	public String list(
			@RequestParam(name = "status", required = false) String status,
			@RequestParam(name = "view", defaultValue = "FLAT") String view,
			@RequestParam(name = "certainty", required = false) String certainty,
			@RequestParam(name = "assetId", required = false) Long assetId,
			@RequestParam(name = "softwareId", required = false) Long softwareId,
			@RequestParam(name = "severity", required = false) String severity,
			Model model
	) {
		String v = (view == null) ? "FLAT" : view.trim().toUpperCase(Locale.ROOT);
		String effective = (status == null) ? "OPEN" : status.trim().toUpperCase(Locale.ROOT);
		String c = normalizeCertainty(certainty);
		String sev = normalizeSeverity(severity);

		List<Alert> alerts = alertService.list(effective, assetId, softwareId);

		alerts = applyCertaintyFilter(alerts, c);
		alerts = applySeverityFilter(alerts, sev);

		model.addAttribute("status", effective);
		model.addAttribute("view", v);
		model.addAttribute("certainty", c);
		model.addAttribute("assetId", assetId);
		model.addAttribute("softwareId", softwareId);
		model.addAttribute("severity", sev);

		if ("ASSET".equals(v)) {
			model.addAttribute("rows", buildAssetRows(alerts));
			return "alerts/by_asset";
		}
		if ("SOFTWARE".equals(v)) {
			model.addAttribute("rows", buildSoftwareRows(alerts));
			return "alerts/by_software";
		}

		model.addAttribute("alerts", alerts);
		return "alerts/list";
	}

	@GetMapping("/alerts/by-software")
	public String bySoftware(
			@RequestParam(name = "status", required = false) String status,
			@RequestParam(name = "certainty", required = false) String certainty,
			Model model
	) {
		String effective = (status == null) ? "OPEN" : status.trim().toUpperCase(Locale.ROOT);
		String c = normalizeCertainty(certainty);

		List<Alert> alerts = alertService.list(effective, null, null);
		alerts = applyCertaintyFilter(alerts, c);

		model.addAttribute("rows", buildSoftwareRows(alerts));
		model.addAttribute("status", effective);
		model.addAttribute("view", "SOFTWARE");
		model.addAttribute("certainty", c);
		model.addAttribute("assetId", null);
		model.addAttribute("softwareId", null);

		return "alerts/by_software";
	}

	private static String normalizeCertainty(String certainty) {
		String c = (certainty == null) ? "ALL" : certainty.trim().toUpperCase(Locale.ROOT);
		return ALLOWED_CERTAINTY.contains(c) ? c : "ALL";
	}

	private static List<Alert> applyCertaintyFilter(List<Alert> alerts, String certaintyKey) {
		if (alerts == null || alerts.isEmpty()) return alerts;
		if (certaintyKey == null || "ALL".equals(certaintyKey)) return alerts;

		if ("UNCONFIRMED".equals(certaintyKey)) {
			return alerts.stream()
					.filter(a -> a.getCertainty() == AlertCertainty.UNCONFIRMED)
					.toList();
		}
		if ("CONFIRMED".equals(certaintyKey)) {
			return alerts.stream()
					.filter(a -> a.getCertainty() == null || a.getCertainty() == AlertCertainty.CONFIRMED)
					.toList();
		}
		return alerts;
	}

	private static List<AssetAggRow> buildAssetRows(List<Alert> alerts) {
		List<Alert> liveAlerts = alerts.stream()
				.filter(a -> a.getSoftwareInstall() != null)
				.filter(a -> a.getSoftwareInstall().getAsset() != null)
				.toList();

		Map<Long, List<Alert>> byAsset = new LinkedHashMap<>();
		for (Alert a : liveAlerts) {
			Long assetId = a.getSoftwareInstall().getAsset().getId();
			byAsset.computeIfAbsent(assetId, k -> new ArrayList<>()).add(a);
		}

		List<AssetAggRow> rows = new ArrayList<>();
		for (var e : byAsset.entrySet()) {
			Long assetId = e.getKey();
			List<Alert> list = e.getValue();

			String assetName = list.get(0).getSoftwareInstall().getAsset().getName();
			int total = list.size();

			int critical = 0, high = 0, medium = 0, low = 0, none = 0;
			Severity top = Severity.NONE;

			for (Alert a : list) {
				Severity s = a.getVulnerability() == null ? Severity.NONE : a.getVulnerability().getSeverity();
				if (s == null) s = Severity.NONE;

				switch (s) {
					case CRITICAL -> critical++;
					case HIGH -> high++;
					case MEDIUM -> medium++;
					case LOW -> low++;
					default -> none++;
				}
				if (sevRank(s) > sevRank(top)) top = s;
			}

			LocalDateTime lastSeen = list.stream()
					.map(Alert::getLastSeenAt)
					.filter(Objects::nonNull)
					.max(Comparator.naturalOrder())
					.orElse(null);

			long softwareCount = list.stream()
					.map(a -> a.getSoftwareInstall().getId())
					.distinct()
					.count();

			rows.add(new AssetAggRow(assetId, assetName, (int) softwareCount, total, top,
					critical, high, medium, low, none, lastSeen));
		}

		return rows.stream()
				.sorted((a, b) -> {
					int s = Integer.compare(sevRank(b.topSeverity), sevRank(a.topSeverity));
					if (s != 0) return s;
					int t = Integer.compare(b.totalAlerts, a.totalAlerts);
					if (t != 0) return t;
					return Long.compare(b.assetId, a.assetId);
				})
				.collect(Collectors.toList());
	}

	private static List<SoftwareAggRow> buildSoftwareRows(List<Alert> alerts) {
		List<Alert> liveAlerts = alerts.stream()
				.filter(a -> a.getSoftwareInstall() != null)
				.filter(a -> a.getSoftwareInstall().getAsset() != null)
				.toList();

		Map<Long, List<Alert>> bySoftware = new LinkedHashMap<>();
		for (Alert a : liveAlerts) {
			Long swId = a.getSoftwareInstall().getId();
			bySoftware.computeIfAbsent(swId, k -> new ArrayList<>()).add(a);
		}

		List<SoftwareAggRow> rows = new ArrayList<>();
		for (var e : bySoftware.entrySet()) {
			Long softwareInstallId = e.getKey();
			List<Alert> list = e.getValue();

			SoftwareInstall si = list.get(0).getSoftwareInstall();
			Long assetId = si.getAsset().getId();
			String assetName = si.getAsset().getName();

			String vendor = safe(si.getVendor());
			String product = safe(si.getProduct());
			String version = safe(si.getVersion());

			int total = list.size();

			int critical = 0, high = 0, medium = 0, low = 0, none = 0;
			Severity top = Severity.NONE;

			for (Alert a : list) {
				Severity s = a.getVulnerability() == null ? Severity.NONE : a.getVulnerability().getSeverity();
				if (s == null) s = Severity.NONE;

				switch (s) {
					case CRITICAL -> critical++;
					case HIGH -> high++;
					case MEDIUM -> medium++;
					case LOW -> low++;
					default -> none++;
				}
				if (sevRank(s) > sevRank(top)) top = s;
			}

			LocalDateTime lastSeen = list.stream()
					.map(Alert::getLastSeenAt)
					.filter(Objects::nonNull)
					.max(Comparator.naturalOrder())
					.orElse(null);

			rows.add(new SoftwareAggRow(softwareInstallId, assetId, assetName,
					vendor, product, version, total, top,
					critical, high, medium, low, none, lastSeen));
		}

		return rows.stream()
				.sorted((a, b) -> {
					int s = Integer.compare(sevRank(b.topSeverity), sevRank(a.topSeverity));
					if (s != 0) return s;
					int t = Integer.compare(b.totalAlerts, a.totalAlerts);
					if (t != 0) return t;
					return Long.compare(b.softwareInstallId, a.softwareInstallId);
				})
				.collect(Collectors.toList());
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

	private static String safe(String s) {
		return (s == null) ? "" : s;
	}

	private static List<CloseReason> manualCloseReasons() {
		return Arrays.stream(CloseReason.values())
				.filter(r -> r != CloseReason.INVENTORY_REPLACED)
				.filter(r -> r != CloseReason.NO_LONGER_OBSERVED)
				.toList();
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
			LocalDateTime lastSeenAt
	) {}

	public record SoftwareAggRow(
			Long softwareInstallId,
			Long assetId,
			String assetName,
			String vendor,
			String product,
			String version,
			int totalAlerts,
			Severity topSeverity,
			int critical,
			int high,
			int medium,
			int low,
			int none,
			LocalDateTime lastSeenAt
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
		model.addAttribute("closeReasons", manualCloseReasons());
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
			model.addAttribute("closeReasons", manualCloseReasons());
			return "alerts/detail";
		}

		alertService.close(id, closeForm.getCloseReason());
		return "redirect:/alerts/" + id;
	}

	@PostMapping("/alerts/{id}/reopen")
	public String reopen(@PathVariable Long id) {
		alertService.reopen(id);
		return "redirect:/alerts/" + id;
	}

	private static String normalizeSeverity(String severity) {
		if (severity == null) return null;
		try {
			return Severity.valueOf(severity.toUpperCase(Locale.ROOT)).name();
		} catch (IllegalArgumentException e) {
			return null;
		}
	}

	private static List<Alert> applySeverityFilter(List<Alert> alerts, String severityKey) {
		if (severityKey == null) return alerts;

		Severity target = Severity.valueOf(severityKey);

		return alerts.stream()
				.filter(a -> {
					if (a.getVulnerability() == null) return false;
					Severity s = a.getVulnerability().getSeverity();
					return s == target;
				})
				.toList();
	}
}