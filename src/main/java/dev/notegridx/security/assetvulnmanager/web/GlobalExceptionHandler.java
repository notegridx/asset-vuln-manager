package dev.notegridx.security.assetvulnmanager.web;

import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public String handleMaxUploadSize(MaxUploadSizeExceededException ex, Model model) {

        model.addAttribute(
                "error",
                "Uploaded file is too large. Maximum allowed size is 200MB."
        );

        return "admin/cpe_sync";
    }
}