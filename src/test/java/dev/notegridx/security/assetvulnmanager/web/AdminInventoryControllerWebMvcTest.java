package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.ImportRun;
import dev.notegridx.security.assetvulnmanager.domain.UnresolvedMapping;
import dev.notegridx.security.assetvulnmanager.repository.UnresolvedMappingRepository;
import dev.notegridx.security.assetvulnmanager.service.AdminInventoryReadService;
import dev.notegridx.security.assetvulnmanager.service.DemoModeService;
import dev.notegridx.security.assetvulnmanager.service.UnresolvedQuickAddService;
import dev.notegridx.security.assetvulnmanager.service.UnresolvedResolutionService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = AdminInventoryController.class)
@ActiveProfiles("mysqltest")
@WithMockUser(username = "admin", roles = "ADMIN")
class AdminInventoryControllerWebMvcTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AdminInventoryReadService adminInventoryReadService;

    @MockitoBean
    private UnresolvedMappingRepository unresolvedMappingRepository;

    @MockitoBean
    private UnresolvedResolutionService unresolvedResolutionService;

    @MockitoBean
    private UnresolvedQuickAddService unresolvedQuickAddService;

    @MockitoBean
    private DemoModeService demoModeService;

    @Test
    @DisplayName("GET /admin/import-runs returns import run list")
    void importRuns_ok() throws Exception {
        ImportRun run1 = mock(ImportRun.class);
        ImportRun run2 = mock(ImportRun.class);

        when(adminInventoryReadService.findImportRuns()).thenReturn(List.of(run1, run2));

        mockMvc.perform(get("/admin/import-runs"))
                .andExpect(status().isOk())
                .andExpect(view().name("admin/import_runs"))
                .andExpect(model().attributeExists("runs"));

        verify(adminInventoryReadService).findImportRuns();
    }

    @Test
    @DisplayName("GET /admin/unresolved uses read service and returns unresolved page")
    void unresolved_ok() throws Exception {
        UnresolvedMapping mapping1 = mock(UnresolvedMapping.class);
        UnresolvedMapping mapping2 = mock(UnresolvedMapping.class);

        when(adminInventoryReadService.findUnresolvedMappings(
                any(), any(), any(), any(), any(), any(), anyInt(), anyInt()
        )).thenReturn(new AdminInventoryReadService.UnresolvedListView(
                List.of(
                        new AdminInventoryReadService.UnresolvedReviewRow(
                                2L,
                                null,
                                mapping2,
                                null,
                                null,
                                null,
                                null,
                                null,
                                null,
                                null,
                                AdminInventoryReadService.CanonicalStatusView.UNRESOLVABLE,
                                null,
                                null,
                                null,
                                null
                        ),
                        new AdminInventoryReadService.UnresolvedReviewRow(
                                1L,
                                null,
                                mapping1,
                                null,
                                null,
                                null,
                                null,
                                null,
                                null,
                                null,
                                AdminInventoryReadService.CanonicalStatusView.UNRESOLVABLE,
                                null,
                                null,
                                null,
                                null
                        )
                ),
                "all",
                null,
                null,
                false,
                null,
                null,
                0,
                50,
                3,
                120,
                List.of(0, 1, 2)
        ));

        mockMvc.perform(get("/admin/unresolved"))
                .andExpect(status().isOk())
                .andExpect(view().name("admin/unresolved"))
                .andExpect(model().attributeExists("mappings"))
                .andExpect(model().attribute("status", "all"))
                .andExpect(model().attribute("runId", nullValue()))
                .andExpect(model().attribute("q", nullValue()))
                .andExpect(model().attribute("activeOnly", nullValue()))
                .andExpect(model().attribute("activeOnlyPresent", nullValue()))
                .andExpect(model().attribute("id", nullValue()))
                .andExpect(model().attribute("page", 0))
                .andExpect(model().attribute("size", 50))
                .andExpect(model().attribute("totalPages", 3))
                .andExpect(model().attribute("totalElements", 120L))
                .andExpect(model().attribute("pagerItems", List.of(0, 1, 2)));

        verify(adminInventoryReadService).findUnresolvedMappings(
                eq("all"),
                isNull(),
                isNull(),
                isNull(),
                isNull(),
                isNull(),
                eq(0),
                eq(50)
        );
    }
}