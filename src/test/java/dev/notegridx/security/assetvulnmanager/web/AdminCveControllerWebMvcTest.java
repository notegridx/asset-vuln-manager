package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.AdminRun;
import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import dev.notegridx.security.assetvulnmanager.infra.nvd.NvdCveFeedClient;
import dev.notegridx.security.assetvulnmanager.service.AdminCveFeedSyncService;
import dev.notegridx.security.assetvulnmanager.service.AdminJobAlreadyRunningException;
import dev.notegridx.security.assetvulnmanager.service.AdminRunReadService;
import dev.notegridx.security.assetvulnmanager.service.CveFeedSyncService;
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

@WebMvcTest(controllers = AdminCveController.class)
@ActiveProfiles("mysqltest")
@WithMockUser(username = "admin", roles = "ADMIN")
class AdminCveControllerWebMvcTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AdminCveFeedSyncService adminCveFeedSyncService;

    @MockitoBean
    private AdminRunReadService adminRunReadService;

    @Test
    @DisplayName("GET /admin/cve/sync returns page with defaults and last run")
    void view_returnsPageWithDefaultsAndLastRun() throws Exception {
        AdminRun run = mock(AdminRun.class);

        doAnswer(invocation -> {
            var model = invocation.getArgument(0, org.springframework.ui.Model.class);
            model.addAttribute("lastRun", run);
            model.addAttribute("lastParams", Map.of("kind", "MODIFIED"));
            model.addAttribute("lastResult", Map.of("vulnerabilitiesParsed", 10));
            return null;
        }).when(adminRunReadService).bindLastRun(
                any(),
                eq(AdminJobType.CVE_FEED_SYNC),
                eq(AdminRunReadService.ParseErrorStyle.MESSAGE_AND_RAW)
        );

        mockMvc.perform(get("/admin/cve/sync"))
                .andExpect(status().isOk())
                .andExpect(view().name("admin/cve_sync"))
                .andExpect(model().attribute("kind", "MODIFIED"))
                .andExpect(model().attribute("year", nullValue()))
                .andExpect(model().attribute("force", false))
                .andExpect(model().attribute("maxItems", 2_000_000))
                .andExpect(model().attribute("lastRun", run))
                .andExpect(model().attribute("lastParams", Map.of("kind", "MODIFIED")))
                .andExpect(model().attribute("lastResult", Map.of("vulnerabilitiesParsed", 10)));

        verify(adminRunReadService).bindLastRun(
                any(),
                eq(AdminJobType.CVE_FEED_SYNC),
                eq(AdminRunReadService.ParseErrorStyle.MESSAGE_AND_RAW)
        );
        verifyNoInteractions(adminCveFeedSyncService);
    }

    @Test
    @DisplayName("POST /admin/cve/sync with YEAR and missing year returns validation error")
    void run_yearWithoutYear_returnsValidationError() throws Exception {
        doAnswer(invocation -> {
            var model = invocation.getArgument(0, org.springframework.ui.Model.class);
            model.addAttribute("lastRun", null);
            model.addAttribute("lastParams", null);
            model.addAttribute("lastResult", null);
            return null;
        }).when(adminRunReadService).bindLastRun(
                any(),
                eq(AdminJobType.CVE_FEED_SYNC),
                eq(AdminRunReadService.ParseErrorStyle.MESSAGE_AND_RAW)
        );

        mockMvc.perform(post("/admin/cve/sync")
                        .with(csrf())
                        .param("kind", "YEAR")
                        .param("force", "false")
                        .param("maxItems", "100"))
                .andExpect(status().isOk())
                .andExpect(view().name("admin/cve_sync"))
                .andExpect(model().attribute("kind", "YEAR"))
                .andExpect(model().attribute("year", nullValue()))
                .andExpect(model().attribute("force", false))
                .andExpect(model().attribute("maxItems", 100))
                .andExpect(model().attribute("error", "Year is required when selecting YEAR feed."))
                .andExpect(model().attribute("lastRun", nullValue()))
                .andExpect(model().attribute("lastParams", nullValue()))
                .andExpect(model().attribute("lastResult", nullValue()));

        verifyNoInteractions(adminCveFeedSyncService);
        verify(adminRunReadService).bindLastRun(
                any(),
                eq(AdminJobType.CVE_FEED_SYNC),
                eq(AdminRunReadService.ParseErrorStyle.MESSAGE_AND_RAW)
        );
    }

    @Test
    @DisplayName("POST /admin/cve/sync runs feed sync and shows result")
    void run_success_returnsResult() throws Exception {
        CveFeedSyncService.SyncResult result = mock(CveFeedSyncService.SyncResult.class);
        AdminRun run = mock(AdminRun.class);

        when(adminCveFeedSyncService.runSync(NvdCveFeedClient.FeedKind.RECENT, null, true, 500))
                .thenReturn(result);

        doAnswer(invocation -> {
            var model = invocation.getArgument(0, org.springframework.ui.Model.class);
            model.addAttribute("lastRun", run);
            model.addAttribute("lastParams", Map.of("kind", "RECENT"));
            model.addAttribute("lastResult", Map.of("vulnerabilitiesParsed", 20));
            return null;
        }).when(adminRunReadService).bindLastRun(
                any(),
                eq(AdminJobType.CVE_FEED_SYNC),
                eq(AdminRunReadService.ParseErrorStyle.MESSAGE_AND_RAW)
        );

        mockMvc.perform(post("/admin/cve/sync")
                        .with(csrf())
                        .param("kind", "RECENT")
                        .param("force", "true")
                        .param("maxItems", "500"))
                .andExpect(status().isOk())
                .andExpect(view().name("admin/cve_sync"))
                .andExpect(model().attribute("kind", "RECENT"))
                .andExpect(model().attribute("year", nullValue()))
                .andExpect(model().attribute("force", true))
                .andExpect(model().attribute("maxItems", 500))
                .andExpect(model().attribute("result", result))
                .andExpect(model().attribute("lastRun", run))
                .andExpect(model().attribute("lastParams", Map.of("kind", "RECENT")))
                .andExpect(model().attribute("lastResult", Map.of("vulnerabilitiesParsed", 20)));

        verify(adminCveFeedSyncService).runSync(NvdCveFeedClient.FeedKind.RECENT, null, true, 500);
        verify(adminRunReadService).bindLastRun(
                any(),
                eq(AdminJobType.CVE_FEED_SYNC),
                eq(AdminRunReadService.ParseErrorStyle.MESSAGE_AND_RAW)
        );
    }

    @Test
    @DisplayName("POST /admin/cve/sync returns already running error when job is active")
    void run_whenAlreadyRunning_returnsError() throws Exception {
        when(adminCveFeedSyncService.runSync(NvdCveFeedClient.FeedKind.MODIFIED, null, false, 100))
                .thenThrow(new AdminJobAlreadyRunningException("CVE feed sync is already running."));

        doAnswer(invocation -> {
            var model = invocation.getArgument(0, org.springframework.ui.Model.class);
            model.addAttribute("lastRun", null);
            model.addAttribute("lastParams", null);
            model.addAttribute("lastResult", null);
            return null;
        }).when(adminRunReadService).bindLastRun(
                any(),
                eq(AdminJobType.CVE_FEED_SYNC),
                eq(AdminRunReadService.ParseErrorStyle.MESSAGE_AND_RAW)
        );

        mockMvc.perform(post("/admin/cve/sync")
                        .with(csrf())
                        .param("kind", "MODIFIED")
                        .param("force", "false")
                        .param("maxItems", "100"))
                .andExpect(status().isOk())
                .andExpect(view().name("admin/cve_sync"))
                .andExpect(model().attribute("kind", "MODIFIED"))
                .andExpect(model().attribute("year", nullValue()))
                .andExpect(model().attribute("force", false))
                .andExpect(model().attribute("maxItems", 100))
                .andExpect(model().attribute("error", "CVE feed sync is already running."))
                .andExpect(model().attribute("lastRun", nullValue()))
                .andExpect(model().attribute("lastParams", nullValue()))
                .andExpect(model().attribute("lastResult", nullValue()));

        verify(adminCveFeedSyncService).runSync(NvdCveFeedClient.FeedKind.MODIFIED, null, false, 100);
        verify(adminRunReadService).bindLastRun(
                any(),
                eq(AdminJobType.CVE_FEED_SYNC),
                eq(AdminRunReadService.ParseErrorStyle.MESSAGE_AND_RAW)
        );
    }
}