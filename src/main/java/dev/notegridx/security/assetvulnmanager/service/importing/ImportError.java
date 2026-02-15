package dev.notegridx.security.assetvulnmanager.service.importing;

public record ImportError(
        int lineNo,
        String code,
        String message,
        String rawLine
) {}
