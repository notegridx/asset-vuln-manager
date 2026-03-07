package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.service.AssetService;
import dev.notegridx.security.assetvulnmanager.service.SoftwareInstallService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.Mockito.*;
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
                .andExpect(model().attributeHasFieldErrors("softwareInstallForm", "product"));
    }
}