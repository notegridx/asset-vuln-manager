package dev.notegridx.security.assetvulnmanager.service;

public class DemoReadOnlyException extends RuntimeException {

    public DemoReadOnlyException(String message) {
        super(message);
    }
}