package dev.notegridx.security.assetvulnmanager.web;

import java.util.List;

import dev.notegridx.security.assetvulnmanager.domain.AdminRun;
import dev.notegridx.security.assetvulnmanager.repository.AdminRunRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AdminRunController {

    private final AdminRunRepository adminRunRepository;

    public AdminRunController(AdminRunRepository adminRunRepository) {
        this.adminRunRepository = adminRunRepository;
    }

    @GetMapping("/admin/runs")
    public String runs(Model model) {
        List<AdminRun> runs = adminRunRepository.findTop200ByOrderByStartedAtDescIdDesc();
        model.addAttribute("runs", runs);
        return "admin/runs";
    }
}