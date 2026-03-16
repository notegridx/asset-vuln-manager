package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.ImportRun;
import dev.notegridx.security.assetvulnmanager.domain.UnresolvedMapping;
import dev.notegridx.security.assetvulnmanager.repository.UnresolvedMappingRepository;
import dev.notegridx.security.assetvulnmanager.service.AdminInventoryReadService;
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
import static org.mockito.Mockito.*;
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

        when(adminInventoryReadService.findUnresolvedMappings(null, null, null, null, null))
                .thenReturn(new AdminInventoryReadService.UnresolvedListView(
                        List.of(mapping1, mapping2),
                        "NEW",
                        null,
                        true,
                        null,
                        null
                ));

        mockMvc.perform(get("/admin/unresolved"))
                .andExpect(status().isOk())
                .andExpect(view().name("admin/unresolved"))
                .andExpect(model().attributeExists("mappings"))
                .andExpect(model().attribute("status", "NEW"))
                .andExpect(model().attribute("runId", nullValue()))
                .andExpect(model().attribute("activeOnly", true))
                .andExpect(model().attribute("activeOnlyPresent", nullValue()));

        verify(adminInventoryReadService).findUnresolvedMappings(null, null, null, null, null);
    }
}