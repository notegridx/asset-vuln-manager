package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.service.AdminCanonicalBackfillService;
import dev.notegridx.security.assetvulnmanager.service.CanonicalCpeLinkingService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.data.domain.Sort;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

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
        when(softwareRepo.findAll()).thenReturn(List.of());
        when(softwareRepo.findAll(any(Sort.class))).thenReturn(List.of());
        when(linker.stats(anyCollection())).thenReturn(emptyStats());

        mockMvc.perform(get("/admin/canonical"))
                .andExpect(status().isOk())
                .andExpect(view().name("admin/canonical"))
                .andExpect(model().attribute("page", 0))
                .andExpect(model().attribute("size", 50))
                .andExpect(model().attribute("filter", "all"))
                .andExpect(model().attribute("totalFilteredRows", 0))
                .andExpect(model().attribute("pageRowStart", 0))
                .andExpect(model().attribute("pageRowEnd", 0))
                .andExpect(model().attributeExists("rows"))
                .andExpect(model().attributeExists("rowPage"))
                .andExpect(model().attributeExists("sizeOptions"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Rows per page")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Previous page")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Next page")));

        verify(assetRepo).findAll(any(Sort.class));
        verify(softwareRepo).findAll();
        verify(softwareRepo).findAll(any(Sort.class));
        verify(linker).stats(anyCollection());
    }

    @Test
    @DisplayName("GET /admin/canonical accepts custom page and size")
    void view_acceptsCustomPageAndSize() throws Exception {
        when(assetRepo.findAll(any(Sort.class))).thenReturn(List.of());
        when(softwareRepo.findAll()).thenReturn(List.of());
        when(softwareRepo.findAll(any(Sort.class))).thenReturn(List.of());
        when(linker.stats(anyCollection())).thenReturn(emptyStats());

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
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Showing")));

        verify(assetRepo).findAll(any(Sort.class));
        verify(softwareRepo).findAll();
        verify(softwareRepo).findAll(any(Sort.class));
        verify(linker).stats(anyCollection());
    }

    private static CanonicalCpeLinkingService.MappingStats emptyStats() {
        return new CanonicalCpeLinkingService.MappingStats(
                0, // total
                0, // vendorOnlyLinkedSql
                0, // fullyLinkedSql
                0, // notLinkedSql
                0, // linkedValid
                0, // linkedStale
                0, // fullyResolvable
                0, // vendorResolvableOnly
                0, // unresolvable
                0  // needsNormalization
        );
    }
}