package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.service.AdminCanonicalBackfillService;
import dev.notegridx.security.assetvulnmanager.service.CanonicalCpeLinkingService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
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
                eq(null),
                eq("all"),
                eq(PageRequest.of(0, 50))
        );
        verify(softwareRepo, never()).findCanonicalBaseRows(any(), any(), any());
    }

    @Test
    @DisplayName("GET /admin/canonical accepts custom page and size")
    void view_acceptsCustomPageAndSize() throws Exception {
        when(assetRepo.findAll(any(Sort.class))).thenReturn(List.of());
        when(softwareRepo.findCanonicalSqlPage(
                eq(null),
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
                eq(null),
                eq("chrome"),
                eq("notLinked"),
                eq(PageRequest.of(1, 200))
        );
        verify(softwareRepo, never()).findCanonicalBaseRows(any(), any(), any());
    }

    @Test
    @DisplayName("GET /admin/canonical uses base-row path for non-SQL filter")
    void view_nonSqlFilter_usesBaseRowsPath() throws Exception {
        when(assetRepo.findAll(any(Sort.class))).thenReturn(List.of());
        when(softwareRepo.findCanonicalBaseRows(eq(null), eq(null), eq("chrome"))).thenReturn(List.of());

        mockMvc.perform(get("/admin/canonical")
                        .param("filter", "linkedValid")
                        .param("q", "chrome"))
                .andExpect(status().isOk())
                .andExpect(view().name("admin/canonical"))
                .andExpect(model().attribute("filter", "linkedValid"))
                .andExpect(model().attribute("q", "chrome"))
                .andExpect(model().attributeExists("rowPage"));

        verify(assetRepo).findAll(any(Sort.class));
        verify(softwareRepo).findCanonicalBaseRows(eq(null), eq(null), eq("chrome"));
        verify(softwareRepo, never()).findCanonicalSqlPage(any(), any(), any(), any(), any());
    }

    @Test
    @DisplayName("GET /admin/canonical filters by asset id and exposes assets for selector")
    void view_filtersByAssetId_andExposesAssetsForSelector() throws Exception {
        Asset asset1 = new Asset("Alpha");
        ReflectionTestUtils.setField(asset1, "id", 1L);

        Asset asset2 = new Asset("Beta");
        ReflectionTestUtils.setField(asset2, "id", 2L);

        when(assetRepo.findAll(any(Sort.class))).thenReturn(List.of(asset1, asset2));
        when(softwareRepo.findCanonicalSqlPage(
                eq(2L),
                isNull(),
                isNull(),
                eq("all"),
                any(Pageable.class)
        )).thenReturn(Page.empty());

        mockMvc.perform(get("/admin/canonical")
                        .param("asset", "2"))
                .andExpect(status().isOk())
                .andExpect(view().name("admin/canonical"))
                .andExpect(model().attribute("asset", 2L))
                .andExpect(model().attributeExists("assets"))
                .andExpect(content().string(containsString("Alpha")))
                .andExpect(content().string(containsString("Beta")));

        verify(assetRepo).findAll(any(Sort.class));
        verify(softwareRepo).findCanonicalSqlPage(
                eq(2L),
                isNull(),
                isNull(),
                eq("all"),
                any(Pageable.class)
        );
    }

    @Test
    @DisplayName("POST /admin/canonical/link-disabled disables canonical link and clears canonical fields")
    void setLinkDisabled_true_clearsCanonicalFields() throws Exception {
        Asset asset = new Asset("test-asset");
        SoftwareInstall softwareInstall = new SoftwareInstall(asset, "VirtualBox");
        ReflectionTestUtils.setField(softwareInstall, "id", 1L);

        softwareInstall.updateDetails(
                "Oracle",
                "VirtualBox",
                "7.0.10",
                "cpe:2.3:a:oracle:virtualbox:7.0.10:*:*:*:*:*:*:*"
        );
        softwareInstall.linkCanonical(10L, 20L);

        when(softwareRepo.findById(1L)).thenReturn(Optional.of(softwareInstall));
        when(softwareRepo.save(any(SoftwareInstall.class))).thenAnswer(inv -> inv.getArgument(0));

        mockMvc.perform(post("/admin/canonical/link-disabled")
                        .with(csrf())
                        .param("softwareId", "1")
                        .param("disabled", "true")
                        .param("redirect", "/admin/canonical"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/canonical"))
                .andExpect(flash().attributeExists("success"));

        assertThat(softwareInstall.isCanonicalLinkDisabled()).isTrue();
        assertThat(softwareInstall.getCpeVendorId()).isNull();
        assertThat(softwareInstall.getCpeProductId()).isNull();
        assertThat(softwareInstall.getCpeName()).isNull();

        verify(softwareRepo).findById(1L);
        verify(softwareRepo).save(softwareInstall);
    }

    @Test
    @DisplayName("POST /admin/canonical/link-disabled enables canonical link without restoring canonical fields")
    void setLinkDisabled_false_enablesFlagOnly() throws Exception {
        Asset asset = new Asset("test-asset");
        SoftwareInstall softwareInstall = new SoftwareInstall(asset, "VirtualBox");
        ReflectionTestUtils.setField(softwareInstall, "id", 2L);

        softwareInstall.disableCanonicalLink();

        when(softwareRepo.findById(2L)).thenReturn(Optional.of(softwareInstall));
        when(softwareRepo.save(any(SoftwareInstall.class))).thenAnswer(inv -> inv.getArgument(0));

        mockMvc.perform(post("/admin/canonical/link-disabled")
                        .with(csrf())
                        .param("softwareId", "2")
                        .param("disabled", "false")
                        .param("redirect", "/admin/canonical"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/canonical"))
                .andExpect(flash().attributeExists("success"));

        assertThat(softwareInstall.isCanonicalLinkDisabled()).isFalse();
        assertThat(softwareInstall.getCpeVendorId()).isNull();
        assertThat(softwareInstall.getCpeProductId()).isNull();
        assertThat(softwareInstall.getCpeName()).isNull();

        verify(softwareRepo).findById(2L);
        verify(softwareRepo).save(softwareInstall);
    }

    @Test
    @DisplayName("POST /admin/canonical/link-disabled returns error when software install is not found")
    void setLinkDisabled_notFound() throws Exception {
        when(softwareRepo.findById(anyLong())).thenReturn(Optional.empty());

        mockMvc.perform(post("/admin/canonical/link-disabled")
                        .with(csrf())
                        .param("softwareId", "999")
                        .param("disabled", "true")
                        .param("redirect", "/admin/canonical"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/canonical"))
                .andExpect(flash().attributeExists("error"));

        verify(softwareRepo).findById(999L);
        verify(softwareRepo, never()).save(any());
    }
}