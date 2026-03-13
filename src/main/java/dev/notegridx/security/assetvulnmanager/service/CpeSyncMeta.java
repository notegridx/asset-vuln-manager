package dev.notegridx.security.assetvulnmanager.service;

public record CpeSyncMeta(
        String sha256,
        String lastModified,
        Long size
) {
    public boolean isEmpty() {
        return sha256 == null && lastModified == null && size == null;
    }
}