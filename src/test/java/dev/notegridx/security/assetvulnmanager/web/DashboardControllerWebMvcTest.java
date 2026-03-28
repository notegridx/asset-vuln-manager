package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.Vulnerability;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityRepository;
import dev.notegridx.security.assetvulnmanager.service.DashboardStatsService;
import dev.notegridx.security.assetvulnmanager.service.DemoModeService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.data.domain.PageImpl;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDate;
import java.util.List;

import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.hamcrest.Matchers.nullValue;

@WebMvcTest(controllers = DashboardController.class)
@ActiveProfiles("mysqltest")
@WithMockUser(username = "admin", roles = "ADMIN")
class DashboardControllerWebMvcTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private DashboardStatsService dashboardStatsService;

    @MockitoBean
    private VulnerabilityRepository vulnerabilityRepository;

    @MockitoBean
    private DemoModeService demoModeService;

    @Test
    @DisplayName("GET / redirects to /dashboard")
    void root_redirectsToDashboard() throws Exception {
        mockMvc.perform(get("/"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/dashboard"));
    }

    @Test
    @DisplayName("GET /dashboard returns dashboard page with stats and async top placeholders")
    void dashboard_ok() throws Exception {
        DashboardStatsService.DashboardViewStats stats =
                new DashboardStatsService.DashboardViewStats(
                        10L,   // assets
                        20L,   // installs
                        30L,   // vulns

                        40L,   // openAlerts
                        25L,   // openAlertsConfirmed
                        15L,   // openAlertsUnconfirmed

                        5L,    // openAlertsCritical
                        3L,    // openAlertsCriticalConfirmed
                        2L,    // openAlertsCriticalUnconfirmed

                        12L,   // openAlertsHigh
                        8L,    // openAlertsHighConfirmed
                        4L,    // openAlertsHighUnconfirmed

                        18L,   // openAlertsMedium
                        11L,   // openAlertsMediumConfirmed
                        7L,    // openAlertsMediumUnconfirmed

                        5L,    // openAlertsLow
                        3L,    // openAlertsLowConfirmed
                        2L,    // openAlertsLowUnconfirmed

                        6L,    // unmappedInstalls
                        100L,  // cpeVendors
                        200L,  // cpeProducts
                        false  // needsSetup
                );

        Vulnerability v1 = mock(Vulnerability.class);
        Vulnerability v2 = mock(Vulnerability.class);

        when(dashboardStatsService.load()).thenReturn(stats);
        when(vulnerabilityRepository.countCriticalWithoutAffectedCpes()).thenReturn(2L);
        when(vulnerabilityRepository.findCriticalWithoutAffectedCpes(any()))
                .thenReturn(new PageImpl<>(List.of(v1, v2)));

        mockMvc.perform(get("/dashboard"))
                .andExpect(status().isOk())
                .andExpect(view().name("dashboard"))

                .andExpect(model().attribute("assets", 10L))
                .andExpect(model().attribute("installs", 20L))
                .andExpect(model().attribute("vulns", 30L))

                .andExpect(model().attribute("openAlerts", 40L))
                .andExpect(model().attribute("openAlertsConfirmed", 25L))
                .andExpect(model().attribute("openAlertsUnconfirmed", 15L))

                .andExpect(model().attribute("openAlertsCritical", 5L))
                .andExpect(model().attribute("openAlertsCriticalConfirmed", 3L))
                .andExpect(model().attribute("openAlertsCriticalUnconfirmed", 2L))

                .andExpect(model().attribute("openAlertsHigh", 12L))
                .andExpect(model().attribute("openAlertsHighConfirmed", 8L))
                .andExpect(model().attribute("openAlertsHighUnconfirmed", 4L))

                .andExpect(model().attribute("openAlertsMedium", 18L))
                .andExpect(model().attribute("openAlertsMediumConfirmed", 11L))
                .andExpect(model().attribute("openAlertsMediumUnconfirmed", 7L))

                .andExpect(model().attribute("openAlertsLow", 5L))
                .andExpect(model().attribute("openAlertsLowConfirmed", 3L))
                .andExpect(model().attribute("openAlertsLowUnconfirmed", 2L))

                .andExpect(model().attribute("unmappedInstalls", 6L))
                .andExpect(model().attribute("cpeVendors", 100L))
                .andExpect(model().attribute("cpeProducts", 200L))
                .andExpect(model().attribute("needsSetup", false))

                .andExpect(model().attribute("criticalNoCpeCount", 2L))
                .andExpect(model().attribute("criticalNoCpe", hasSize(2)))

                .andExpect(model().attribute("topRange", "D30"))
                .andExpect(model().attribute("topRangeLabel", "Last 30 days"))
                .andExpect(model().attribute("from", nullValue()))
                .andExpect(model().attribute("to", nullValue()))

                .andExpect(model().attribute("topVendors", empty()))
                .andExpect(model().attribute("topProducts", empty()));

        verify(dashboardStatsService).load();
        verify(vulnerabilityRepository).countCriticalWithoutAffectedCpes();
        verify(vulnerabilityRepository).findCriticalWithoutAffectedCpes(any());
        verifyNoMoreInteractions(vulnerabilityRepository);
    }

    @Test
    @DisplayName("GET /dashboard with custom range keeps range values and async top placeholders")
    void dashboard_customRange_ok() throws Exception {
        DashboardStatsService.DashboardViewStats stats =
                new DashboardStatsService.DashboardViewStats(
                        1L, 2L, 3L,
                        4L, 3L, 1L,
                        1L, 1L, 0L,
                        1L, 1L, 0L,
                        1L, 1L, 0L,
                        1L, 0L, 1L,
                        9L, 10L, 11L,
                        true
                );

        when(dashboardStatsService.load()).thenReturn(stats);
        when(vulnerabilityRepository.countCriticalWithoutAffectedCpes()).thenReturn(0L);
        when(vulnerabilityRepository.findCriticalWithoutAffectedCpes(any()))
                .thenReturn(new PageImpl<>(List.of()));

        mockMvc.perform(get("/dashboard")
                        .param("range", "CUSTOM")
                        .param("from", "2026-03-01")
                        .param("to", "2026-03-10"))
                .andExpect(status().isOk())
                .andExpect(view().name("dashboard"))
                .andExpect(model().attribute("topRange", "CUSTOM"))
                .andExpect(model().attribute("topRangeLabel", "Custom"))
                .andExpect(model().attribute("from", LocalDate.of(2026, 3, 1)))
                .andExpect(model().attribute("to", LocalDate.of(2026, 3, 10)))
                .andExpect(model().attribute("topVendors", empty()))
                .andExpect(model().attribute("topProducts", empty()))
                .andExpect(model().attribute("criticalNoCpeCount", 0L))
                .andExpect(model().attribute("criticalNoCpe", empty()));

        verify(dashboardStatsService).load();
        verify(vulnerabilityRepository).countCriticalWithoutAffectedCpes();
        verify(vulnerabilityRepository).findCriticalWithoutAffectedCpes(any());
    }
}