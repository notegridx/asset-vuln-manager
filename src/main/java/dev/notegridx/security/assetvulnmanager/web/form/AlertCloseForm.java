package dev.notegridx.security.assetvulnmanager.web.form;

import dev.notegridx.security.assetvulnmanager.domain.enums.CloseReason;
import jakarta.validation.constraints.NotNull;

public class AlertCloseForm {

    @NotNull(message = "Close reason is required")
    private CloseReason closeReason;

    public CloseReason getCloseReason() {
        return closeReason;
    }

    public void setCloseReason(CloseReason closeReason) {
        this.closeReason = closeReason;
    }
}
