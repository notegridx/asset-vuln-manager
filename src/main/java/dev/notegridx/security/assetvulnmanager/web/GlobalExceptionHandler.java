package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.service.DemoReadOnlyException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(DemoReadOnlyException.class)
    public Object handleDemoReadOnly(
            DemoReadOnlyException ex,
            HttpServletRequest request,
            HttpServletResponse response,
            Model model
    ) {
        boolean htmx = "true".equalsIgnoreCase(request.getHeader("HX-Request"));

        if (htmx) {
            HttpHeaders headers = new HttpHeaders();
            headers.add(
                    "HX-Trigger",
                    "{\"demoError\":{\"message\":\"" + escapeJson(ex.getMessage()) + "\"}}"
            );
            return new ResponseEntity<>("", headers, HttpStatus.FORBIDDEN);
        }

        response.setStatus(HttpStatus.FORBIDDEN.value());
        model.addAttribute("message", ex.getMessage());

        // Minimal-change option:
        // keep using the existing error template and only fix status + message.
        return "error/403";
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public String handleMaxUploadSize(MaxUploadSizeExceededException ex, Model model) {
        model.addAttribute(
                "error",
                "Uploaded file is too large. Maximum allowed size is 200MB."
        );
        return "admin/cpe_sync";
    }

    private static String escapeJson(String s) {
        if (s == null) {
            return "";
        }
        return s
                .replace("\\", "\\\\")
                .replace("\"", "\\\"");
    }
}