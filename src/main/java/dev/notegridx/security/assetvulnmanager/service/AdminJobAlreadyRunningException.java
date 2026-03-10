package dev.notegridx.security.assetvulnmanager.service;

public class AdminJobAlreadyRunningException extends RuntimeException {
    public AdminJobAlreadyRunningException(String message) {
        super(message);
    }
}