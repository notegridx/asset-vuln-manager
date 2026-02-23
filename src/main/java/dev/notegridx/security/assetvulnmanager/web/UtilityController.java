package dev.notegridx.security.assetvulnmanager.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class UtilityController {

    @GetMapping("utility/osquery")
    public String osqueryConverter() {
        return "utility/osquery";
    }
}