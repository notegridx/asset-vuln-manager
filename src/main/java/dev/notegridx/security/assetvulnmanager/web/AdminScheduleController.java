package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.service.AdminScheduleService;
import dev.notegridx.security.assetvulnmanager.service.DemoModeService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AdminScheduleController {

    private final AdminScheduleService adminScheduleService;
    private final DemoModeService demoModeService;

    public AdminScheduleController(
            AdminScheduleService adminScheduleService,
            DemoModeService demoModeService
    ) {
        this.adminScheduleService = adminScheduleService;
        this.demoModeService = demoModeService;
    }

    @GetMapping("/admin/system/schedule")
    public String view(Model model) {
        model.addAttribute("schedule", adminScheduleService.getCveDeltaSchedule());
        model.addAttribute("generateAlertsSchedule", adminScheduleService.getGenerateAlertsSchedule());
        return "admin/schedule";
    }

    @PostMapping("/admin/system/schedule/cve-delta")
    public String saveCveDelta(
            @RequestParam(name = "enabled", defaultValue = "false") boolean enabled,
            @RequestParam(name = "intervalHours", defaultValue = "24") int intervalHours,
            @RequestParam(name = "daysBack", defaultValue = "1") int daysBack,
            @RequestParam(name = "maxResults", defaultValue = "200") int maxResults,
            Model model
    ) {
        demoModeService.assertWritable();

        try {
            AdminScheduleService.CveDeltaScheduleView schedule =
                    adminScheduleService.saveCveDeltaSchedule(
                            enabled,
                            intervalHours,
                            daysBack,
                            maxResults
                    );

            model.addAttribute("schedule", schedule);
            model.addAttribute("generateAlertsSchedule", adminScheduleService.getGenerateAlertsSchedule());
            model.addAttribute("message", "CVE Delta Update schedule saved.");
            return "admin/schedule";

        } catch (IllegalArgumentException ex) {
            model.addAttribute(
                    "schedule",
                    new AdminScheduleService.CveDeltaScheduleView(
                            enabled,
                            intervalHours,
                            daysBack,
                            maxResults,
                            null,
                            null,
                            null
                    )
            );
            model.addAttribute("generateAlertsSchedule", adminScheduleService.getGenerateAlertsSchedule());
            model.addAttribute("error", ex.getMessage());
            return "admin/schedule";
        }
    }

    @PostMapping("/admin/system/schedule/generate-alerts")
    public String saveGenerateAlerts(
            @RequestParam(name = "enabled", defaultValue = "false") boolean enabled,
            @RequestParam(name = "intervalHours", defaultValue = "24") int intervalHours,
            Model model
    ) {
        demoModeService.assertWritable();

        try {
            AdminScheduleService.GenerateAlertsScheduleView schedule =
                    adminScheduleService.saveGenerateAlertsSchedule(
                            enabled,
                            intervalHours
                    );

            model.addAttribute("schedule", adminScheduleService.getCveDeltaSchedule());
            model.addAttribute("generateAlertsSchedule", schedule);
            model.addAttribute("message", "Generate Alerts schedule saved.");
            return "admin/schedule";

        } catch (IllegalArgumentException ex) {
            model.addAttribute("schedule", adminScheduleService.getCveDeltaSchedule());
            model.addAttribute(
                    "generateAlertsSchedule",
                    new AdminScheduleService.GenerateAlertsScheduleView(
                            enabled,
                            intervalHours,
                            null,
                            null,
                            null
                    )
            );
            model.addAttribute("error", ex.getMessage());
            return "admin/schedule";
        }
    }
}