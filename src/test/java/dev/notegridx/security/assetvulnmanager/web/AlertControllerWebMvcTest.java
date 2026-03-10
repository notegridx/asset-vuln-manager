package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.Alert;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertStatus;
import dev.notegridx.security.assetvulnmanager.domain.enums.CloseReason;
import dev.notegridx.security.assetvulnmanager.service.AlertService;
import jakarta.persistence.EntityNotFoundException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = AlertController.class)
@ActiveProfiles("test")
@WithMockUser(username = "test", roles = "ADMIN")
class AlertControllerWebMvcTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AlertService alertService;

    // =========================
    // LIST
    // =========================

    @Test
    @DisplayName("GET /alerts returns flat list by default")
    void list_defaultFlatView() throws Exception {

        when(alertService.list(anyString(), nullable(Long.class), nullable(Long.class)))
                .thenReturn(List.of());

        mockMvc.perform(get("/alerts"))
                .andExpect(status().isOk())
                .andExpect(view().name("alerts/list"))
                .andExpect(model().attribute("status", "OPEN"))
                .andExpect(model().attribute("view", "FLAT"))
                .andExpect(model().attribute("certainty", "ALL"))
                .andExpect(model().attributeExists("alerts"));
    }

    @Test
    @DisplayName("GET /alerts?view=ASSET returns asset grouped page")
    void list_assetView() throws Exception {

        when(alertService.list(anyString(), nullable(Long.class), nullable(Long.class)))
                .thenReturn(List.of());

        mockMvc.perform(get("/alerts").param("view", "ASSET"))
                .andExpect(status().isOk())
                .andExpect(view().name("alerts/by_asset"))
                .andExpect(model().attribute("view", "ASSET"))
                .andExpect(model().attributeExists("rows"));
    }

    @Test
    @DisplayName("GET /alerts?view=SOFTWARE returns software grouped page")
    void list_softwareView() throws Exception {

        when(alertService.list(anyString(), nullable(Long.class), nullable(Long.class)))
                .thenReturn(List.of());

        mockMvc.perform(get("/alerts").param("view", "SOFTWARE"))
                .andExpect(status().isOk())
                .andExpect(view().name("alerts/by_software"))
                .andExpect(model().attribute("view", "SOFTWARE"))
                .andExpect(model().attributeExists("rows"));
    }

    @Test
    @DisplayName("GET /alerts/by-software returns grouped page")
    void bySoftware_returnsGroupedPage() throws Exception {

        when(alertService.list(anyString(), isNull(), isNull()))
                .thenReturn(List.of());

        mockMvc.perform(get("/alerts/by-software"))
                .andExpect(status().isOk())
                .andExpect(view().name("alerts/by_software"))
                .andExpect(model().attribute("view", "SOFTWARE"))
                .andExpect(model().attributeExists("rows"));
    }

    // =========================
    // DETAIL
    // =========================

    @Test
    @DisplayName("GET /alerts/{id} returns detail page")
    void detail_ok() throws Exception {

        Alert alert = mock(Alert.class);
        when(alertService.getRequired(1L)).thenReturn(alert);

        mockMvc.perform(get("/alerts/1"))
                .andExpect(status().isOk())
                .andExpect(view().name("alerts/detail"))
                .andExpect(model().attributeExists("alert"))
                .andExpect(model().attributeExists("closeForm"))
                .andExpect(model().attributeExists("closeReasons"));
    }

    @Test
    @DisplayName("GET /alerts/{id} returns 404 when alert does not exist")
    void detail_notFound_returns404() throws Exception {

        when(alertService.getRequired(999L))
                .thenThrow(new EntityNotFoundException("Alert not found: 999"));

        mockMvc.perform(get("/alerts/999"))
                .andExpect(status().isNotFound());
    }

    // =========================
    // CERTAINTY FILTER
    // =========================

    @Test
    @DisplayName("GET /alerts?certainty=CONFIRMED")
    void list_certaintyConfirmed() throws Exception {

        when(alertService.list(anyString(), nullable(Long.class), nullable(Long.class)))
                .thenReturn(List.of());

        mockMvc.perform(get("/alerts")
                        .param("certainty", "CONFIRMED"))
                .andExpect(status().isOk())
                .andExpect(model().attribute("certainty", "CONFIRMED"));
    }

    @Test
    @DisplayName("GET /alerts?certainty=UNCONFIRMED")
    void list_certaintyUnconfirmed() throws Exception {

        when(alertService.list(anyString(), nullable(Long.class), nullable(Long.class)))
                .thenReturn(List.of());

        mockMvc.perform(get("/alerts")
                        .param("certainty", "UNCONFIRMED"))
                .andExpect(status().isOk())
                .andExpect(model().attribute("certainty", "UNCONFIRMED"));
    }

    @Test
    @DisplayName("invalid certainty becomes ALL")
    void list_invalidCertainty_becomesAll() throws Exception {

        when(alertService.list(anyString(), nullable(Long.class), nullable(Long.class)))
                .thenReturn(List.of());

        mockMvc.perform(get("/alerts")
                        .param("certainty", "INVALID"))
                .andExpect(status().isOk())
                .andExpect(model().attribute("certainty", "ALL"));
    }

    // =========================
    // CLOSE
    // =========================

    @Test
    @DisplayName("POST /alerts/{id}/close closes alert")
    void close_ok() throws Exception {

        Alert alert = mock(Alert.class);
        when(alert.getStatus()).thenReturn(AlertStatus.OPEN);

        when(alertService.getRequired(1L)).thenReturn(alert);
        when(alertService.close(eq(1L), eq(CloseReason.FALSE_POSITIVE)))
                .thenReturn(alert);

        mockMvc.perform(post("/alerts/1/close")
                        .with(csrf())
                        .param("closeReason", "FALSE_POSITIVE"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/alerts/1"));
    }

    @Test
    @DisplayName("POST /alerts/{id}/close validation error")
    void close_validationError() throws Exception {

        Alert alert = mock(Alert.class);
        when(alertService.getRequired(1L)).thenReturn(alert);

        mockMvc.perform(post("/alerts/1/close")
                        .with(csrf()))
                .andExpect(status().isOk())
                .andExpect(view().name("alerts/detail"))
                .andExpect(model().hasErrors())
                .andExpect(model().attributeExists("alert"))
                .andExpect(model().attributeExists("closeReasons"));
    }

}