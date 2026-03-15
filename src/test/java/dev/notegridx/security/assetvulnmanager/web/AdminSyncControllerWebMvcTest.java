package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.AdminRun;
import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import dev.notegridx.security.assetvulnmanager.service.AdminCveDeltaUpdateService;
import dev.notegridx.security.assetvulnmanager.service.AdminJobAlreadyRunningException;
import dev.notegridx.security.assetvulnmanager.service.AdminRunReadService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = AdminSyncController.class)
@ActiveProfiles("mysqltest")
@WithMockUser(username = "admin", roles = "ADMIN")
class AdminSyncControllerWebMvcTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AdminCveDeltaUpdateService deltaUpdateService;

    @MockitoBean
    private AdminRunReadService adminRunReadService;

    @Test
    @DisplayName("GET /admin/sync returns page with last run")
    void view_returnsPageWithLastRun() throws Exception {
        AdminRun run = mock(AdminRun.class);

        doAnswer(invocation -> {
            var model = invocation.getArgument(0, org.springframework.ui.Model.class);
            model.addAttribute("lastRun", run);
            model.addAttribute("lastParams", Map.of("daysBack", 1, "maxResults", 200));
            model.addAttribute("lastResult", Map.of("fetched", 10));
            return null;
        }).when(adminRunReadService).bindLastRun(
                any(),
                eq(AdminJobType.CVE_DELTA_UPDATE),
                eq(AdminRunReadService.ParseErrorStyle.SIMPLE_CLASS_NAME)
        );

        mockMvc.perform(get("/admin/sync"))
                .andExpect(status().isOk())
                .andExpect(view().name("admin/sync"))
                .andExpect(model().attribute("lastRun", run))
                .andExpect(model().attribute("lastParams", Map.of("daysBack", 1, "maxResults", 200)))
                .andExpect(model().attribute("lastResult", Map.of("fetched", 10)));

        verify(adminRunReadService).bindLastRun(
                any(),
                eq(AdminJobType.CVE_DELTA_UPDATE),
                eq(AdminRunReadService.ParseErrorStyle.SIMPLE_CLASS_NAME)
        );
        verifyNoInteractions(deltaUpdateService);
    }

    @Test
    @DisplayName("POST /admin/sync runs delta update and shows result")
    void run_success_returnsResult() throws Exception {
        AdminCveDeltaUpdateService.DeltaUpdateResult result =
                new AdminCveDeltaUpdateService.DeltaUpdateResult(11, 22, 33);
        AdminRun run = mock(AdminRun.class);

        when(deltaUpdateService.runDeltaUpdate(3, 50)).thenReturn(result);

        doAnswer(invocation -> {
            var model = invocation.getArgument(0, org.springframework.ui.Model.class);
            model.addAttribute("lastRun", run);
            model.addAttribute("lastParams", Map.of("daysBack", 3, "maxResults", 50));
            model.addAttribute("lastResult", Map.of("fetched", 33));
            return null;
        }).when(adminRunReadService).bindLastRun(
                any(),
                eq(AdminJobType.CVE_DELTA_UPDATE),
                eq(AdminRunReadService.ParseErrorStyle.SIMPLE_CLASS_NAME)
        );

        mockMvc.perform(post("/admin/sync")
                        .with(csrf())
                        .param("daysBack", "3")
                        .param("maxResults", "50"))
                .andExpect(status().isOk())
                .andExpect(view().name("admin/sync"))
                .andExpect(model().attribute("daysBack", 3))
                .andExpect(model().attribute("maxResults", 50))
                .andExpect(model().attribute("result", result))
                .andExpect(model().attribute("lastRun", run))
                .andExpect(model().attribute("lastParams", Map.of("daysBack", 3, "maxResults", 50)))
                .andExpect(model().attribute("lastResult", Map.of("fetched", 33)));

        verify(deltaUpdateService).runDeltaUpdate(3, 50);
        verify(adminRunReadService).bindLastRun(
                any(),
                eq(AdminJobType.CVE_DELTA_UPDATE),
                eq(AdminRunReadService.ParseErrorStyle.SIMPLE_CLASS_NAME)
        );
    }

    @Test
    @DisplayName("POST /admin/sync returns already running error")
    void run_whenAlreadyRunning_returnsError() throws Exception {
        when(deltaUpdateService.runDeltaUpdate(1, 200))
                .thenThrow(new AdminJobAlreadyRunningException("CVE delta update is already running."));

        doAnswer(invocation -> {
            var model = invocation.getArgument(0, org.springframework.ui.Model.class);
            model.addAttribute("lastRun", null);
            model.addAttribute("lastParams", null);
            model.addAttribute("lastResult", null);
            return null;
        }).when(adminRunReadService).bindLastRun(
                any(),
                eq(AdminJobType.CVE_DELTA_UPDATE),
                eq(AdminRunReadService.ParseErrorStyle.SIMPLE_CLASS_NAME)
        );

        mockMvc.perform(post("/admin/sync").with(csrf()))
                .andExpect(status().isOk())
                .andExpect(view().name("admin/sync"))
                .andExpect(model().attribute("daysBack", 1))
                .andExpect(model().attribute("maxResults", 200))
                .andExpect(model().attribute("error", "CVE delta update is already running."))
                .andExpect(model().attribute("lastRun", nullValue()))
                .andExpect(model().attribute("lastParams", nullValue()))
                .andExpect(model().attribute("lastResult", nullValue()));

        verify(deltaUpdateService).runDeltaUpdate(1, 200);
        verify(adminRunReadService).bindLastRun(
                any(),
                eq(AdminJobType.CVE_DELTA_UPDATE),
                eq(AdminRunReadService.ParseErrorStyle.SIMPLE_CLASS_NAME)
        );
    }
}