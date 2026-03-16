package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.service.AdminCanonicalBackfillService;
import dev.notegridx.security.assetvulnmanager.service.CanonicalCpeLinkingService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@WebMvcTest(controllers = AdminCanonicalController.class)
@ActiveProfiles("mysqltest")
@WithMockUser(username = "admin", roles = "ADMIN")
class AdminCanonicalControllerWebMvcTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AssetRepository assetRepo;

    @MockitoBean
    private SoftwareInstallRepository softwareRepo;

    @MockitoBean
    private CanonicalCpeLinkingService linker;

    @MockitoBean
    private AdminCanonicalBackfillService adminCanonicalBackfillService;

    @Test
    @DisplayName("GET /admin/canonical uses default page=0 and size=50")
    void view_usesDefaultPagination() throws Exception {
        when(assetRepo.findAll(any(Sort.class))).thenReturn(List.of());
        when(softwareRepo.findCanonicalSqlPage(
                eq(null),
                eq(null),
                eq("all"),
                eq(PageRequest.of(0, 50))
        )).thenReturn(new PageImpl<>(List.of(), PageRequest.of(0, 50), 0));

        mockMvc.perform(get("/admin/canonical"))
                .andExpect(status().isOk())
                .andExpect(view().name("admin/canonical"))
                .andExpect(model().attribute("page", 0))
                .andExpect(model().attribute("size", 50))
                .andExpect(model().attribute("filter", "all"))
                .andExpect(model().attribute("totalFilteredRows", 0L))
                .andExpect(model().attribute("pageRowStart", 0))
                .andExpect(model().attribute("pageRowEnd", 0))
                .andExpect(model().attributeExists("rows"))
                .andExpect(model().attributeExists("rowPage"))
                .andExpect(model().attributeExists("sizeOptions"))
                .andExpect(content().string(containsString("Rows per page")))
                .andExpect(content().string(containsString("Previous page")))
                .andExpect(content().string(containsString("Next page")));

        verify(assetRepo).findAll(any(Sort.class));
        verify(softwareRepo).findCanonicalSqlPage(
                eq(null),
                eq(null),
                eq("all"),
                eq(PageRequest.of(0, 50))
        );
        verify(softwareRepo, never()).findCanonicalBaseRows(any(), any());
    }

    @Test
    @DisplayName("GET /admin/canonical accepts custom page and size")
    void view_acceptsCustomPageAndSize() throws Exception {
        when(assetRepo.findAll(any(Sort.class))).thenReturn(List.of());
        when(softwareRepo.findCanonicalSqlPage(
                eq(null),
                eq("chrome"),
                eq("notLinked"),
                eq(PageRequest.of(1, 200))
        )).thenReturn(new PageImpl<>(List.of(), PageRequest.of(1, 200), 0));

        mockMvc.perform(get("/admin/canonical")
                        .param("page", "1")
                        .param("size", "200")
                        .param("filter", "notLinked")
                        .param("q", "chrome"))
                .andExpect(status().isOk())
                .andExpect(view().name("admin/canonical"))
                .andExpect(model().attribute("page", 1))
                .andExpect(model().attribute("size", 200))
                .andExpect(model().attribute("filter", "notLinked"))
                .andExpect(model().attribute("q", "chrome"))
                .andExpect(model().attributeExists("rowPage"))
                .andExpect(content().string(containsString("Showing")));

        verify(assetRepo).findAll(any(Sort.class));
        verify(softwareRepo).findCanonicalSqlPage(
                eq(null),
                eq("chrome"),
                eq("notLinked"),
                eq(PageRequest.of(1, 200))
        );
        verify(softwareRepo, never()).findCanonicalBaseRows(any(), any());
    }

    @Test
    @DisplayName("GET /admin/canonical uses base-row path for non-SQL filter")
    void view_nonSqlFilter_usesBaseRowsPath() throws Exception {
        when(assetRepo.findAll(any(Sort.class))).thenReturn(List.of());
        when(softwareRepo.findCanonicalBaseRows(eq(null), eq("chrome"))).thenReturn(List.of());

        mockMvc.perform(get("/admin/canonical")
                        .param("filter", "linkedValid")
                        .param("q", "chrome"))
                .andExpect(status().isOk())
                .andExpect(view().name("admin/canonical"))
                .andExpect(model().attribute("filter", "linkedValid"))
                .andExpect(model().attribute("q", "chrome"))
                .andExpect(model().attributeExists("rowPage"));

        verify(assetRepo).findAll(any(Sort.class));
        verify(softwareRepo).findCanonicalBaseRows(eq(null), eq("chrome"));
        verify(softwareRepo, never()).findCanonicalSqlPage(any(), any(), any(), any());
    }
}