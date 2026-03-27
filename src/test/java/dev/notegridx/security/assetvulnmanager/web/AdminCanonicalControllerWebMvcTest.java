package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.service.AdminCanonicalBackfillService;
import dev.notegridx.security.assetvulnmanager.service.AdminJobAlreadyRunningException;
import dev.notegridx.security.assetvulnmanager.service.AdminRunRecorder;
import dev.notegridx.security.assetvulnmanager.service.CanonicalBackfillService;
import dev.notegridx.security.assetvulnmanager.service.CanonicalCpeLinkingService;
import dev.notegridx.security.assetvulnmanager.service.DemoModeService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@WebMvcTest(controllers = AdminCanonicalController.class)
@Import(TestSecurityConfig.class)
@ActiveProfiles("mysqltest")
@WithMockUser(username = "admin", roles = "ADMIN")
class AdminCanonicalControllerWebMvcTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AdminCanonicalController controller;

    @MockitoBean
    private AssetRepository assetRepo;

    @MockitoBean
    private SoftwareInstallRepository softwareRepo;

    @MockitoBean
    private CanonicalCpeLinkingService linker;

    @MockitoBean
    private AdminCanonicalBackfillService adminCanonicalBackfillService;

    @MockitoBean
    private DemoModeService demoModeService;

    @MockitoBean
    private CpeVendorRepository cpeVendorRepository;

    @MockitoBean
    private CpeProductRepository cpeProductRepository;

    @MockitoBean
    private AdminRunRecorder adminRunRecorder;

    @BeforeEach
    void setUpControllerCaches() {
        ReflectionTestUtils.setField(
                controller,
                "cachedStats",
                mock(CanonicalCpeLinkingService.MappingStats.class)
        );
        ReflectionTestUtils.setField(
                controller,
                "cachedStatsAtMillis",
                System.currentTimeMillis()
        );

        ReflectionTestUtils.setField(controller, "cachedAssets", null);
        ReflectionTestUtils.setField(controller, "cachedAssetsAtMillis", 0L);
    }

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
                .andExpect(model().attribute("currentQuery", "?filter=all&page=0&size=50"));

        verify(assetRepo).findAll(any(Sort.class));
        verify(softwareRepo).findCanonicalSqlPage(
                eq(null),
                eq(null),
                eq(null),
                eq("all"),
                eq(PageRequest.of(0, 50))
        );
        verify(softwareRepo, never()).findCanonicalBasePage(any(), any(), any(), any());
        verify(softwareRepo, never()).findCanonicalBaseRows(any(), any(), any());
    }

    @Test
    @DisplayName("GET /admin/canonical accepts custom page and normalizes size")
    void view_acceptsCustomPageAndNormalizesSize() throws Exception {
        when(assetRepo.findAll(any(Sort.class))).thenReturn(List.of());
        when(softwareRepo.findCanonicalSqlPage(
                eq(null),
                eq(null),
                eq("chrome"),
                eq("notLinked"),
                eq(PageRequest.of(2, 200))
        )).thenReturn(new PageImpl<>(List.of(), PageRequest.of(2, 200), 0));

        mockMvc.perform(get("/admin/canonical")
                        .param("filter", "notLinked")
                        .param("q", "chrome")
                        .param("page", "2")
                        .param("size", "120"))
                .andExpect(status().isOk())
                .andExpect(view().name("admin/canonical"))
                .andExpect(model().attribute("page", 2))
                .andExpect(model().attribute("size", 200))
                .andExpect(model().attribute("filter", "notLinked"))
                .andExpect(model().attribute("q", "chrome"))
                .andExpect(model().attribute("totalFilteredRows", 0L))
                .andExpect(model().attribute("currentQuery", "?filter=notLinked&q=chrome&page=2&size=200"));

        verify(softwareRepo).findCanonicalSqlPage(
                eq(null),
                eq(null),
                eq("chrome"),
                eq("notLinked"),
                eq(PageRequest.of(2, 200))
        );
        verify(softwareRepo, never()).findCanonicalBasePage(any(), any(), any(), any());
        verify(softwareRepo, never()).findCanonicalBaseRows(any(), any(), any());
    }

    @Test
    @DisplayName("GET /admin/canonical uses paged base scan for non-SQL filter")
    void view_nonSqlFilter_usesFindCanonicalBasePage() throws Exception {
        when(assetRepo.findAll(any(Sort.class))).thenReturn(List.of());
        when(softwareRepo.findCanonicalBasePage(
                eq(null),
                eq(null),
                eq("oracle"),
                eq(PageRequest.of(0, 200))
        )).thenReturn(new PageImpl<>(List.of(), PageRequest.of(0, 200), 0));

        mockMvc.perform(get("/admin/canonical")
                        .param("filter", "linkedValid")
                        .param("q", "oracle"))
                .andExpect(status().isOk())
                .andExpect(view().name("admin/canonical"))
                .andExpect(model().attribute("filter", "linkedValid"))
                .andExpect(model().attribute("q", "oracle"))
                .andExpect(model().attribute("page", 0))
                .andExpect(model().attribute("size", 50))
                .andExpect(model().attribute("totalFilteredRows", 0L))
                .andExpect(model().attribute("pageRowStart", 0))
                .andExpect(model().attribute("pageRowEnd", 0));

        verify(softwareRepo).findCanonicalBasePage(
                eq(null),
                eq(null),
                eq("oracle"),
                eq(PageRequest.of(0, 200))
        );
        verify(softwareRepo, never()).findCanonicalSqlPage(any(), any(), any(), any(), any());
        verify(softwareRepo, never()).findCanonicalBaseRows(any(), any(), any());
    }

    @Test
    @DisplayName("POST /admin/canonical/link runs backfill and redirects to requested page")
    void runLinking_success() throws Exception {
        CanonicalBackfillService.BackfillResult result =
                new CanonicalBackfillService.BackfillResult(
                        100,
                        80,
                        10,
                        true,
                        90,
                        10,
                        0,
                        1234L,
                        "1.234",
                        "81.0"
                );

        when(adminCanonicalBackfillService.runBackfill(1000, true)).thenReturn(result);

        mockMvc.perform(post("/admin/canonical/link")
                        .with(csrf())
                        .param("maxRows", "1000")
                        .param("relink", "true")
                        .param("redirect", "/admin/canonical?filter=notLinked"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/canonical?filter=notLinked"))
                .andExpect(flash().attributeExists("backfillResult"));

        verify(adminCanonicalBackfillService).runBackfill(1000, true);
    }

    @Test
    @DisplayName("POST /admin/canonical/link returns flash error when job is already running")
    void runLinking_alreadyRunning() throws Exception {
        when(adminCanonicalBackfillService.runBackfill(5000000, false))
                .thenThrow(new AdminJobAlreadyRunningException("already running"));

        mockMvc.perform(post("/admin/canonical/link")
                        .with(csrf())
                        .param("redirect", "/admin/canonical"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin/canonical"))
                .andExpect(flash().attribute("error", "already running"));

        verify(adminCanonicalBackfillService).runBackfill(5000000, false);
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