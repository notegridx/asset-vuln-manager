package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.AdminRun;
import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import dev.notegridx.security.assetvulnmanager.service.AdminJobAlreadyRunningException;
import dev.notegridx.security.assetvulnmanager.service.AdminKevSyncService;
import dev.notegridx.security.assetvulnmanager.service.AdminRunReadService;
import dev.notegridx.security.assetvulnmanager.service.KevSyncService;
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

@WebMvcTest(controllers = AdminKevController.class)
@ActiveProfiles("mysqltest")
@WithMockUser(username = "admin", roles = "ADMIN")
class AdminKevControllerWebMvcTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AdminKevSyncService adminKevSyncService;

    @MockitoBean
    private AdminRunReadService adminRunReadService;

    @Test
    @DisplayName("GET /admin/kev/sync returns page with defaults and last run")
    void page_returnsPageWithDefaultsAndLastRun() throws Exception {
        AdminRun run = mock(AdminRun.class);

        doAnswer(invocation -> {
            var model = invocation.getArgument(0, org.springframework.ui.Model.class);
            model.addAttribute("lastRun", run);
            model.addAttribute("lastParams", Map.of("force", false, "maxItems", 50000));
            model.addAttribute("lastResult", Map.of("processedEntries", 350));
            return null;
        }).when(adminRunReadService).bindLastRun(
                any(),
                eq(AdminJobType.KEV_SYNC),
                eq(AdminRunReadService.ParseErrorStyle.MESSAGE_AND_RAW)
        );

        mockMvc.perform(get("/admin/kev/sync"))
                .andExpect(status().isOk())
                .andExpect(view().name("admin/kev_sync"))
                .andExpect(model().attribute("force", false))
                .andExpect(model().attribute("maxItems", 50000))
                .andExpect(model().attribute("lastRun", run))
                .andExpect(model().attribute("lastParams", Map.of("force", false, "maxItems", 50000)))
                .andExpect(model().attribute("lastResult", Map.of("processedEntries", 350)));

        verify(adminRunReadService).bindLastRun(
                any(),
                eq(AdminJobType.KEV_SYNC),
                eq(AdminRunReadService.ParseErrorStyle.MESSAGE_AND_RAW)
        );
        verifyNoInteractions(adminKevSyncService);
    }

    @Test
    @DisplayName("POST /admin/kev/sync runs sync and shows result")
    void run_success_returnsResult() throws Exception {
        KevSyncService.SyncResult result = mock(KevSyncService.SyncResult.class);
        AdminRun run = mock(AdminRun.class);

        when(adminKevSyncService.run(true, 123)).thenReturn(result);

        doAnswer(invocation -> {
            var model = invocation.getArgument(0, org.springframework.ui.Model.class);
            model.addAttribute("lastRun", run);
            model.addAttribute("lastParams", Map.of("force", true, "maxItems", 123));
            model.addAttribute("lastResult", Map.of("processedEntries", 120));
            return null;
        }).when(adminRunReadService).bindLastRun(
                any(),
                eq(AdminJobType.KEV_SYNC),
                eq(AdminRunReadService.ParseErrorStyle.MESSAGE_AND_RAW)
        );

        mockMvc.perform(post("/admin/kev/sync")
                        .with(csrf())
                        .param("force", "true")
                        .param("maxItems", "123"))
                .andExpect(status().isOk())
                .andExpect(view().name("admin/kev_sync"))
                .andExpect(model().attribute("force", true))
                .andExpect(model().attribute("maxItems", 123))
                .andExpect(model().attribute("result", result))
                .andExpect(model().attribute("lastRun", run))
                .andExpect(model().attribute("lastParams", Map.of("force", true, "maxItems", 123)))
                .andExpect(model().attribute("lastResult", Map.of("processedEntries", 120)));

        verify(adminKevSyncService).run(true, 123);
        verify(adminRunReadService).bindLastRun(
                any(),
                eq(AdminJobType.KEV_SYNC),
                eq(AdminRunReadService.ParseErrorStyle.MESSAGE_AND_RAW)
        );
    }

    @Test
    @DisplayName("POST /admin/kev/sync returns already running error")
    void run_whenAlreadyRunning_returnsError() throws Exception {
        when(adminKevSyncService.run(false, 50000))
                .thenThrow(new AdminJobAlreadyRunningException("KEV sync is already running."));

        doAnswer(invocation -> {
            var model = invocation.getArgument(0, org.springframework.ui.Model.class);
            model.addAttribute("lastRun", null);
            model.addAttribute("lastParams", null);
            model.addAttribute("lastResult", null);
            return null;
        }).when(adminRunReadService).bindLastRun(
                any(),
                eq(AdminJobType.KEV_SYNC),
                eq(AdminRunReadService.ParseErrorStyle.MESSAGE_AND_RAW)
        );

        mockMvc.perform(post("/admin/kev/sync").with(csrf()))
                .andExpect(status().isOk())
                .andExpect(view().name("admin/kev_sync"))
                .andExpect(model().attribute("force", false))
                .andExpect(model().attribute("maxItems", 50000))
                .andExpect(model().attribute("error", "KEV sync is already running."))
                .andExpect(model().attribute("lastRun", nullValue()))
                .andExpect(model().attribute("lastParams", nullValue()))
                .andExpect(model().attribute("lastResult", nullValue()));

        verify(adminKevSyncService).run(false, 50000);
        verify(adminRunReadService).bindLastRun(
                any(),
                eq(AdminJobType.KEV_SYNC),
                eq(AdminRunReadService.ParseErrorStyle.MESSAGE_AND_RAW)
        );
    }
}