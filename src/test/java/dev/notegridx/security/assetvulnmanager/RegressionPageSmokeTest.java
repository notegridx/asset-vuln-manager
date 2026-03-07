package dev.notegridx.security.assetvulnmanager;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RegressionPageSmokeTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("Core pages should render with empty test DB")
    void corePages_renderSuccessfully() throws Exception {
        mockMvc.perform(get("/assets"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/software"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/alerts"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/admin/canonical"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/admin/sync"))
                .andExpect(status().isOk());
    }
}