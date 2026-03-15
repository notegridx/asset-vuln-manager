package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.AdminRun;
import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class AdminRunRecorderTest {

    private AdminRunWriteService adminRunWriteService;
    private AdminRunRecorder recorder;

    @BeforeEach
    void setup() {
        adminRunWriteService = mock(AdminRunWriteService.class);
        recorder = new AdminRunRecorder(adminRunWriteService);
    }

    @Test
    @DisplayName("runExclusive: when body succeeds, start and success are called and result is returned")
    void runExclusive_success_callsStartAndSuccess() throws Exception {
        AdminRun run = AdminRun.start(AdminJobType.KEV_SYNC, "{\"force\":false}");

        when(adminRunWriteService.start(eq(AdminJobType.KEV_SYNC), anyMap()))
                .thenReturn(run);

        String result = recorder.runExclusive(
                AdminJobType.KEV_SYNC,
                Map.of("force", false),
                "already running",
                () -> "OK",
                value -> Map.of("result", value)
        );

        assertThat(result).isEqualTo("OK");

        verify(adminRunWriteService).start(AdminJobType.KEV_SYNC, Map.of("force", false));
        verify(adminRunWriteService).success(run, Map.of("result", "OK"));
        verify(adminRunWriteService, never()).failed(any(), any());
    }

    @Test
    @DisplayName("runExclusive: when body throws, failed is called and the exception is rethrown")
    void runExclusive_failure_callsFailedAndRethrows() throws Exception {
        AdminRun run = AdminRun.start(AdminJobType.CVE_FEED_SYNC, "{\"kind\":\"RECENT\"}");

        when(adminRunWriteService.start(eq(AdminJobType.CVE_FEED_SYNC), anyMap()))
                .thenReturn(run);

        IOException ex = new IOException("boom");

        assertThatThrownBy(() -> recorder.runExclusive(
                AdminJobType.CVE_FEED_SYNC,
                Map.of("kind", "RECENT"),
                "already running",
                () -> {
                    throw ex;
                },
                value -> Map.of("unused", value)
        ))
                .isSameAs(ex);

        verify(adminRunWriteService).start(AdminJobType.CVE_FEED_SYNC, Map.of("kind", "RECENT"));
        verify(adminRunWriteService).failed(run, ex);
        verify(adminRunWriteService, never()).success(any(), any());
    }

    @Test
    @DisplayName("runExclusive: running the same jobType concurrently throws AdminJobAlreadyRunningException")
    void runExclusive_reentrantSameJobType_throwsAlreadyRunning() throws Exception {
        AdminRun outerRun = AdminRun.start(AdminJobType.IMPORT, "{\"mode\":\"outer\"}");

        when(adminRunWriteService.start(eq(AdminJobType.IMPORT), anyMap()))
                .thenReturn(outerRun);

        assertThatThrownBy(() -> recorder.runExclusive(
                AdminJobType.IMPORT,
                Map.of("mode", "outer"),
                "already running",
                () -> recorder.runExclusive(
                        AdminJobType.IMPORT,
                        Map.of("mode", "inner"),
                        "already running",
                        () -> "INNER-OK",
                        value -> Map.of("value", value)
                ),
                value -> Map.of("value", value)
        ))
                .isInstanceOf(AdminJobAlreadyRunningException.class)
                .hasMessage("already running");

        verify(adminRunWriteService).start(AdminJobType.IMPORT, Map.of("mode", "outer"));
        verify(adminRunWriteService).failed(
                eq(outerRun),
                argThat(ex -> ex instanceof AdminJobAlreadyRunningException
                        && "already running".equals(ex.getMessage()))
        );
        verify(adminRunWriteService, never()).success(any(), any());
    }
}