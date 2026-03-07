package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.service.AssetService;
import dev.notegridx.security.assetvulnmanager.service.SoftwareInstallService;
import jakarta.persistence.EntityNotFoundException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(controllers = AssetController.class)
@ActiveProfiles("test")
class AssetControllerWebMvcTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AssetService assetService;

    @MockitoBean
    private SoftwareInstallService softwareInstallService;

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
                        .param("externalKey", "asset-001")
                        .param("name", "Test Asset")
                        .param("assetType", "SERVER")
                        .param("owner", "ops")
                        .param("note", "created by test"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/assets"));

        verify(assetService).create(
                "asset-001",
                "Test Asset",
                "SERVER",
                "ops",
                "created by test"
        );
    }

    @Test
    @DisplayName("POST /assets without required name stays on form")
    void create_invalid_returnsNewPage() throws Exception {
        mockMvc.perform(post("/assets")
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
                .create(any(), any(), any(), any(), any());

        mockMvc.perform(post("/assets")
                        .param("externalKey", "asset-001")
                        .param("name", "Test Asset"))
                .andExpect(status().isOk())
                .andExpect(view().name("assets/new"))
                .andExpect(model().attributeHasFieldErrors("assetForm", "externalKey"));
    }

    @Test
    @DisplayName("POST /assets/{id}/delete redirects to list")
    void delete_redirectsToList() throws Exception {
        mockMvc.perform(post("/assets/10/delete"))
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

        mockMvc.perform(get("/assets/1"))
                .andExpect(status().isOk())
                .andExpect(view().name("assets/detail"))
                .andExpect(model().attributeExists("asset"))
                .andExpect(model().attributeExists("installs"));
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
                        .param("vendor", "Microsoft")
                        .param("product", "Visual Studio Code")
                        .param("version", "1.99.0")
                        .param("cpeName", ""))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/assets/1"));

        verify(softwareInstallService).addToAsset(
                same(asset),
                eq("Microsoft"),
                eq("Visual Studio Code"),
                eq("1.99.0"),
                eq("")
        );
    }

    @Test
    @DisplayName("POST /assets/{assetId}/software without product stays on form")
    void createSoftware_invalid_returnsForm() throws Exception {
        Asset asset = mock(Asset.class);
        when(assetService.getRequired(1L)).thenReturn(asset);

        mockMvc.perform(post("/assets/1/software")
                        .param("vendor", "Microsoft")
                        .param("product", "")
                        .param("version", "1.99.0"))
                .andExpect(status().isOk())
                .andExpect(view().name("assets/software_new"))
                .andExpect(model().attributeExists("asset"))
                .andExpect(model().attributeHasFieldErrors("softwareInstallForm", "product"));
    }

    @Test
    @DisplayName("GET /assets/{id}/edit returns edit page")
    void edit_returnsEditPage() throws Exception {
        Asset asset = mock(Asset.class);
        when(assetService.getRequired(1L)).thenReturn(asset);

        mockMvc.perform(get("/assets/1/edit"))
                .andExpect(status().isOk())
                .andExpect(view().name("assets/edit"))
                .andExpect(model().attributeExists("asset"))
                .andExpect(model().attributeExists("assetForm"));
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

    @Test
    @DisplayName("POST /assets/{id}/edit with valid form redirects to detail")
    void update_valid_redirectsToDetail() throws Exception {
        mockMvc.perform(post("/assets/1/edit")
                        .param("externalKey", "asset-001")
                        .param("name", "Updated Asset")
                        .param("assetType", "WORKSTATION")
                        .param("owner", "alice")
                        .param("note", "updated")
                        .param("source", "MANUAL")
                        .param("platform", "windows")
                        .param("osVersion", "11"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/assets/1"));

        verify(assetService).update(
                1L,
                "asset-001",
                "Updated Asset",
                "WORKSTATION",
                "alice",
                "updated",
                "MANUAL",
                "windows",
                "11"
        );
    }

    @Test
    @DisplayName("POST /assets/{id}/edit duplicate external key stays on edit page")
    void update_duplicateExternalKey_returnsEditPage() throws Exception {
        Asset asset = mock(Asset.class);
        when(assetService.getRequired(1L)).thenReturn(asset);

        doThrow(new DataIntegrityViolationException("duplicate"))
                .when(assetService)
                .update(any(), any(), any(), any(), any(), any(), any(), any(), any());

        mockMvc.perform(post("/assets/1/edit")
                        .param("externalKey", "asset-dup")
                        .param("name", "Updated Asset")
                        .param("assetType", "WORKSTATION")
                        .param("owner", "alice")
                        .param("note", "updated")
                        .param("source", "MANUAL")
                        .param("platform", "windows")
                        .param("osVersion", "11"))
                .andExpect(status().isOk())
                .andExpect(view().name("assets/edit"))
                .andExpect(model().attributeExists("asset"))
                .andExpect(model().attributeHasFieldErrors("assetForm", "externalKey"));
    }

    @Test
    @DisplayName("POST /assets/{id}/edit without required name stays on edit page")
    void update_invalid_returnsEditPage() throws Exception {
        Asset asset = mock(Asset.class);
        when(assetService.getRequired(1L)).thenReturn(asset);

        mockMvc.perform(post("/assets/1/edit")
                        .param("externalKey", "asset-001")
                        .param("name", "")
                        .param("assetType", "WORKSTATION"))
                .andExpect(status().isOk())
                .andExpect(view().name("assets/edit"))
                .andExpect(model().attributeExists("asset"))
                .andExpect(model().attributeHasFieldErrors("assetForm", "name"));
    }
}