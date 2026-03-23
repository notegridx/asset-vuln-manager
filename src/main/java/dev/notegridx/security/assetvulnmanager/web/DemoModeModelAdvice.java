package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.service.DemoModeService;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

@ControllerAdvice
public class DemoModeModelAdvice {

    private final DemoModeService demoModeService;

    public DemoModeModelAdvice(DemoModeService demoModeService) {
        this.demoModeService = demoModeService;
    }

    @ModelAttribute("demoMode")
    public boolean demoMode() {
        return demoModeService.isReadOnly();
    }
}