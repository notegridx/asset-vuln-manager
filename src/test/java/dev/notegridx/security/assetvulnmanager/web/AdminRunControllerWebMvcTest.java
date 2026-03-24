package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.service.AdminRunReadService;
import dev.notegridx.security.assetvulnmanager.service.DemoModeService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = AdminRunController.class)
@ActiveProfiles("mysqltest")
@WithMockUser(username = "admin", roles = "ADMIN")
class AdminRunControllerWebMvcTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AdminRunReadService adminRunReadService;

    @MockitoBean
    private DemoModeService demoModeService;

    @Test
    @DisplayName("GET /admin/runs returns admin runs page")
    void list_returnsRunsPage() throws Exception {
        when(adminRunReadService.findRecentRuns(200)).thenReturn(List.of());

        mockMvc.perform(get("/admin/runs"))
                .andExpect(status().isOk())
                .andExpect(view().name("admin/runs"))
                .andExpect(model().attributeExists("runs"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("No admin runs found for the current filters.")));

        verify(adminRunReadService).findRecentRuns(200);
    }
}