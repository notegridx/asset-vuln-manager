package dev.notegridx.security.assetvulnmanager.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class DemoModeService {

    private final boolean readOnly;

    public DemoModeService(@Value("${app.demo.read-only:false}") boolean readOnly) {
        this.readOnly = readOnly;
    }

    public boolean isReadOnly() {
        return readOnly;
    }

    public void assertWritable() {
        if (readOnly) {
            throw new DemoReadOnlyException(
                    "This public demo is read-only. Changes are disabled in the demo environment."
            );
        }
    }
}