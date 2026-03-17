package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.repository.AlertRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.service.AssetService;
import dev.notegridx.security.assetvulnmanager.service.SoftwareInstallService;
import dev.notegridx.security.assetvulnmanager.web.form.SoftwareInstallForm;
import jakarta.persistence.EntityNotFoundException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = AssetController.class)
@ActiveProfiles("mysqltest")
@WithMockUser(username = "test", roles = "ADMIN")
class AssetControllerWebMvcTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AssetService assetService;

    @MockitoBean
    private SoftwareInstallService softwareInstallService;

    @MockitoBean
    private AlertRepository alertRepository;

    @MockitoBean
    private CpeVendorRepository cpeVendorRepository;

    @MockitoBean
    private CpeProductRepository cpeProductRepository;

    @Test
    @DisplayName("GET /assets returns asset list page")
    void list_returnsAssetsPage() throws Exception {
        when(assetService.findAll()).thenReturn(List.of());

        mockMvc.perform(get("/assets"))
                .andExpect(status().isOk())
                .andExpect(view().name("assets/list"))
                .andExpect(model().attributeExists("assets"));
    }

    @Test
    @DisplayName("GET /assets/new returns new form")
    void newForm_returnsNewPage() throws Exception {
        mockMvc.perform(get("/assets/new"))
                .andExpect(status().isOk())
                .andExpect(view().name("assets/new"))
                .andExpect(model().attributeExists("assetForm"));
    }

    @Test
    @DisplayName("POST /assets with valid form redirects to list")
    void create_valid_redirectsToList() throws Exception {
        mockMvc.perform(post("/assets")
                        .with(csrf())
                        .param("externalKey", "asset-001")
                        .param("name", "Test Asset")
                        .param("assetType", "SERVER")
                        .param("owner", "ops")
                        .param("note", "created by test"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/assets"));

        verify(assetService).create(
                eq("asset-001"),
                eq("Test Asset"),
                eq("SERVER"),
                eq("ops"),
                eq("created by test"),
                isNull(),
                isNull(),
                isNull(),
                isNull(),
                isNull(),
                isNull(),
                isNull(),
                isNull(),
                isNull(),
                isNull(),
                isNull(),
                isNull(),
                isNull(),
                isNull(),
                isNull(),
                isNull(),
                isNull(),
                isNull(),
                isNull(),
                isNull(),
                isNull(),
                isNull(),
                isNull(),
                isNull(),
                isNull(),
                isNull()
        );
    }

    @Test
    @DisplayName("POST /assets without required name stays on form")
    void create_invalid_returnsNewPage() throws Exception {
        mockMvc.perform(post("/assets")
                        .with(csrf())
                        .param("externalKey", "asset-001")
                        .param("name", "")
                        .param("assetType", "SERVER"))
                .andExpect(status().isOk())
                .andExpect(view().name("assets/new"))
                .andExpect(model().attributeHasFieldErrors("assetForm", "name"));
    }

    @Test
    @DisplayName("POST /assets duplicate external key stays on form")
    void create_duplicateExternalKey_returnsNewPage() throws Exception {
        doThrow(new DataIntegrityViolationException("duplicate"))
                .when(assetService)
                .create(
                        any(), any(), any(), any(), any(),
                        any(), any(), any(), any(), any(),
                        any(), any(), any(), any(), any(),
                        any(), any(), any(), any(), any(),
                        any(), any(), any(), any(), any(),
                        any(), any(), any(), any(), any(),
                        any()
                );

        mockMvc.perform(post("/assets")
                        .with(csrf())
                        .param("externalKey", "asset-001")
                        .param("name", "Test Asset"))
                .andExpect(status().isOk())
                .andExpect(view().name("assets/new"))
                .andExpect(model().attributeHasFieldErrors("assetForm", "externalKey"));
    }

    @Test
    @DisplayName("POST /assets/{id}/delete redirects to list")
    void delete_redirectsToList() throws Exception {
        mockMvc.perform(post("/assets/10/delete")
                        .with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/assets"));

        verify(assetService).deleteCascade(10L);
    }

    @Test
    @DisplayName("GET /assets/{id} returns detail page")
    void detail_returnsDetailPage() throws Exception {
        Asset asset = mock(Asset.class);

        when(assetService.getRequired(1L)).thenReturn(asset);
        when(softwareInstallService.findByAssetId(1L)).thenReturn(List.of());
        when(alertRepository.countBySoftwareInstallIds(List.of())).thenReturn(List.of());
        when(cpeVendorRepository.findAllById(anyIterable())).thenReturn(List.of());
        when(cpeProductRepository.findAllById(anyIterable())).thenReturn(List.of());

        mockMvc.perform(get("/assets/1"))
                .andExpect(status().isOk())
                .andExpect(view().name("assets/detail"))
                .andExpect(model().attributeExists("asset"))
                .andExpect(model().attributeExists("installs"))
                .andExpect(model().attributeExists("alertCountBySoftwareId"))
                .andExpect(model().attributeExists("vendorNameMap"))
                .andExpect(model().attributeExists("productNameMap"));
    }

    @Test
    @DisplayName("GET /assets/{id} returns 404 when asset does not exist")
    void detail_notFound_returns404() throws Exception {
        when(assetService.getRequired(999L))
                .thenThrow(new EntityNotFoundException("Asset not found. id=999"));

        mockMvc.perform(get("/assets/999"))
                .andExpect(status().isNotFound())
                .andExpect(view().name("error/404"))
                .andExpect(model().attributeExists("message"));
    }

    @Test
    @DisplayName("GET /assets/{assetId}/software/new returns software form")
    void newSoftware_returnsForm() throws Exception {
        Asset asset = mock(Asset.class);
        when(assetService.getRequired(1L)).thenReturn(asset);

        mockMvc.perform(get("/assets/1/software/new"))
                .andExpect(status().isOk())
                .andExpect(view().name("assets/software_new"))
                .andExpect(model().attributeExists("asset"))
                .andExpect(model().attributeExists("softwareInstallForm"));
    }

    @Test
    @DisplayName("POST /assets/{assetId}/software with valid form redirects to asset detail")
    void createSoftware_valid_redirectsToAssetDetail() throws Exception {
        Asset asset = mock(Asset.class);
        when(assetService.getRequired(1L)).thenReturn(asset);

        mockMvc.perform(post("/assets/1/software")
                        .with(csrf())
                        .param("vendor", "Microsoft")
                        .param("product", "Visual Studio Code")
                        .param("version", "1.99.0")
                        .param("cpeName", ""))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/assets/1"));

        verify(softwareInstallService).addToAsset(
                same(asset),
                argThat((SoftwareInstallForm form) ->
                        form != null
                                && "Microsoft".equals(form.getVendor())
                                && "Visual Studio Code".equals(form.getProduct())
                                && "1.99.0".equals(form.getVersion())
                                && "".equals(form.getCpeName())
                )
        );
    }

    @Test
    @DisplayName("GET /assets/{id}/edit returns edit page")
    void edit_returnsEditPage() throws Exception {
        Asset asset = new Asset("Test Asset");
        asset.updateDetails("asset-001", "SERVER", "ops", "note");
        asset.setSource("OSQUERY");
        asset.updateInventory(
                "windows",
                "11",
                "uuid-123",
                "serial-1",
                "Dell",
                "XPS",
                "1.0",
                "host01",
                "host01.local",
                "host01",
                "Intel",
                4,
                8,
                1,
                16384L,
                "x86_64",
                "Dell",
                "ABC",
                "1",
                "board-1",
                "Windows",
                "22631",
                11,
                0,
                1
        );

        when(assetService.getRequired(1L)).thenReturn(asset);

        mockMvc.perform(get("/assets/1/edit"))
                .andExpect(status().isOk())
                .andExpect(view().name("assets/edit"))
                .andExpect(model().attributeExists("asset"))
                .andExpect(model().attributeExists("assetForm"));
    }

    @Test
    @DisplayName("POST /assets/{id}/edit with valid form redirects to detail")
    void update_valid_redirectsToDetail() throws Exception {
        Asset asset = mock(Asset.class);
        when(assetService.getRequired(1L)).thenReturn(asset);

        mockMvc.perform(post("/assets/1/edit")
                        .with(csrf())
                        .param("externalKey", "asset-001")
                        .param("name", "Test Asset")
                        .param("assetType", "SERVER")
                        .param("owner", "ops")
                        .param("note", "updated by test")
                        .param("source", "OSQUERY")
                        .param("platform", "windows")
                        .param("osVersion", "11")
                        .param("systemUuid", "uuid-123")
                        .param("serialNumber", "serial-1")
                        .param("hardwareVendor", "Dell")
                        .param("hardwareModel", "XPS")
                        .param("hardwareVersion", "1.0")
                        .param("computerName", "host01")
                        .param("localHostname", "host01.local")
                        .param("hostname", "host01")
                        .param("cpuBrand", "Intel")
                        .param("cpuPhysicalCores", "4")
                        .param("cpuLogicalCores", "8")
                        .param("cpuSockets", "1")
                        .param("physicalMemory", "16384")
                        .param("arch", "x86_64")
                        .param("boardVendor", "Dell")
                        .param("boardModel", "ABC")
                        .param("boardVersion", "1")
                        .param("boardSerial", "board-1")
                        .param("osName", "Windows")
                        .param("osBuild", "22631")
                        .param("osMajor", "11")
                        .param("osMinor", "0")
                        .param("osPatch", "1"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/assets/1"));

        verify(assetService).update(
                eq(1L),
                eq("asset-001"),
                eq("Test Asset"),
                eq("SERVER"),
                eq("ops"),
                eq("updated by test"),
                eq("OSQUERY"),
                eq("windows"),
                eq("11"),
                eq("uuid-123"),
                eq("serial-1"),
                eq("Dell"),
                eq("XPS"),
                eq("1.0"),
                eq("host01"),
                eq("host01.local"),
                eq("host01"),
                eq("Intel"),
                eq(4),
                eq(8),
                eq(1),
                eq(16384L),
                eq("x86_64"),
                eq("Dell"),
                eq("ABC"),
                eq("1"),
                eq("board-1"),
                eq("Windows"),
                eq("22631"),
                eq(11),
                eq(0),
                eq(1)
        );
    }

    @Test
    @DisplayName("POST /assets/{id}/edit without required name returns edit page")
    void update_invalid_returnsEditPage() throws Exception {
        Asset asset = mock(Asset.class);
        when(assetService.getRequired(1L)).thenReturn(asset);

        mockMvc.perform(post("/assets/1/edit")
                        .with(csrf())
                        .param("externalKey", "asset-001")
                        .param("name", "")
                        .param("assetType", "SERVER"))
                .andExpect(status().isOk())
                .andExpect(view().name("assets/edit"))
                .andExpect(model().attributeExists("asset"))
                .andExpect(model().attributeHasFieldErrors("assetForm", "name"));
    }

    @Test
    @DisplayName("POST /assets/{id}/edit duplicate external key returns edit page")
    void update_duplicateExternalKey_returnsEditPage() throws Exception {
        Asset asset = mock(Asset.class);
        when(assetService.getRequired(1L)).thenReturn(asset);

        doThrow(new DataIntegrityViolationException("duplicate"))
                .when(assetService)
                .update(
                        anyLong(),
                        any(), any(), any(), any(), any(),
                        any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any(),
                        any(), any(), any(), any(), any(), any(), any(), any(), any(), any(),
                        any(), any(), any(), any(), any()
                );

        mockMvc.perform(post("/assets/1/edit")
                        .with(csrf())
                        .param("externalKey", "asset-001")
                        .param("name", "Test Asset")
                        .param("assetType", "SERVER"))
                .andExpect(status().isOk())
                .andExpect(view().name("assets/edit"))
                .andExpect(model().attributeExists("asset"))
                .andExpect(model().attributeHasFieldErrors("assetForm", "externalKey"));
    }

    @Test
    @DisplayName("GET /assets/{id}/edit returns 404 when asset does not exist")
    void edit_notFound_returns404() throws Exception {
        when(assetService.getRequired(999L))
                .thenThrow(new EntityNotFoundException("Asset not found. id=999"));

        mockMvc.perform(get("/assets/999/edit"))
                .andExpect(status().isNotFound())
                .andExpect(view().name("error/404"))
                .andExpect(model().attributeExists("message"));
    }
}