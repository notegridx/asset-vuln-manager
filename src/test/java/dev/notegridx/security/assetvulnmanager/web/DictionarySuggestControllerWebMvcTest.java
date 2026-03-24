package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.domain.SystemSetting;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorRepository;
import dev.notegridx.security.assetvulnmanager.repository.SystemSettingRepository;
import dev.notegridx.security.assetvulnmanager.service.DemoModeService;
import dev.notegridx.security.assetvulnmanager.service.SynonymService;
import dev.notegridx.security.assetvulnmanager.service.VendorProductNormalizer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Optional;

import static dev.notegridx.security.assetvulnmanager.web.AdminSettingsController.KEY_CANONICAL_CANDIDATE_EXACT_LIMIT;
import static dev.notegridx.security.assetvulnmanager.web.AdminSettingsController.KEY_CANONICAL_CANDIDATE_MIN_CHARS;
import static dev.notegridx.security.assetvulnmanager.web.AdminSettingsController.KEY_CANONICAL_CANDIDATE_OTHER_LIMIT;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(DictionarySuggestController.class)
@ActiveProfiles("mysqltest")
@WithMockUser(username = "admin", roles = "ADMIN")
class DictionarySuggestControllerWebMvcTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private CpeVendorRepository vendorRepo;

    @MockitoBean
    private CpeProductRepository productRepo;

    @MockitoBean
    private VendorProductNormalizer normalizer;

    @MockitoBean
    private SynonymService synonymService;

    @MockitoBean
    private SystemSettingRepository systemSettingRepository;

    @MockitoBean
    private DemoModeService demoModeService;

    // =========================================================
    // Vendor suggestion (/api/dict/vendors)
    // =========================================================

    @Test
    @DisplayName("GET /api/dict/vendors falls back from whole-string miss to token match")
    void suggestVendors_fallsBackToToken_whenWholeStringDoesNotMatch() throws Exception {

        CpeVendor git = vendor(10L, "git", "Git");
        CpeVendor github = vendor(11L, "github", "GitHub");

        mockIntSetting(KEY_CANONICAL_CANDIDATE_MIN_CHARS, 2);
        mockIntSetting(KEY_CANONICAL_CANDIDATE_OTHER_LIMIT, 30);

        when(normalizer.normalizeVendor("the git")).thenReturn("the git");

        when(synonymService.canonicalVendorOrSame("the git")).thenReturn("the git");
        when(synonymService.canonicalVendorOrSame("git")).thenReturn("git");

        when(vendorRepo.findTop20ByNameNormStartingWithOrderByNameNormAsc("the git"))
                .thenReturn(List.of());
        when(vendorRepo.findTop20ByNameNormContainingOrderByNameNormAsc("the git"))
                .thenReturn(List.of());

        when(vendorRepo.findTop20ByNameNormStartingWithOrderByNameNormAsc("git"))
                .thenReturn(List.of(git, github));

        mockMvc.perform(get("/api/dict/vendors").param("q", "the git"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("application/json"))
                .andExpect(jsonPath("$[0].value").value("git"))
                .andExpect(jsonPath("$[0].label").value("Git"))
                .andExpect(jsonPath("$[1].value").value("github"))
                .andExpect(jsonPath("$[1].label").value("GitHub"));

        verify(systemSettingRepository).findById(KEY_CANONICAL_CANDIDATE_MIN_CHARS);
        verify(systemSettingRepository).findById(KEY_CANONICAL_CANDIDATE_OTHER_LIMIT);
        verifyNoMoreInteractions(systemSettingRepository);

        verify(normalizer).normalizeVendor("the git");
        verifyNoMoreInteractions(normalizer);

        verify(synonymService).canonicalVendorOrSame("the git");
        verify(synonymService).canonicalVendorOrSame("git");
        verifyNoMoreInteractions(synonymService);

        verify(vendorRepo).findTop20ByNameNormStartingWithOrderByNameNormAsc("the git");
        verify(vendorRepo).findTop20ByNameNormContainingOrderByNameNormAsc("the git");
        verify(vendorRepo).findTop20ByNameNormStartingWithOrderByNameNormAsc("git");
        verify(vendorRepo, never()).findTop20ByNameNormContainingOrderByNameNormAsc("git");
        verifyNoMoreInteractions(vendorRepo);

        verifyNoInteractions(productRepo);
    }

    // =========================================================
    // Product suggestion (/api/dict/products)
    // =========================================================

    @Test
    @DisplayName("GET /api/dict/products resolves vendor via token fallback and returns product suggestions")
    void suggestProducts_resolvesVendorByTokenFallback_andReturnsProducts() throws Exception {

        CpeVendor gitVendor = vendor(10L, "git", "Git");
        CpeProduct gitDesktop = product(101L, gitVendor, "git_desktop", "Git Desktop");

        mockIntSetting(KEY_CANONICAL_CANDIDATE_MIN_CHARS, 2);
        mockIntSetting(KEY_CANONICAL_CANDIDATE_OTHER_LIMIT, 30);

        when(normalizer.normalizeVendor("the git")).thenReturn("the git");
        when(normalizer.normalizeProduct("git desktop")).thenReturn("git desktop");

        when(synonymService.canonicalVendorOrSame("the git")).thenReturn("the git");
        when(synonymService.canonicalVendorOrSame("git")).thenReturn("git");
        when(synonymService.canonicalProductOrSame("git", "git desktop")).thenReturn("git desktop");
        when(synonymService.canonicalProductOrSame("git", "desktop")).thenReturn("desktop");
        when(synonymService.canonicalProductOrSame("git", "git")).thenReturn("git");

        when(vendorRepo.findByNameNorm("the git")).thenReturn(Optional.empty());
        when(vendorRepo.findTop20ByNameNormStartingWithOrderByNameNormAsc("the git"))
                .thenReturn(List.of());
        when(vendorRepo.findTop20ByNameNormContainingOrderByNameNormAsc("the git"))
                .thenReturn(List.of());

        when(vendorRepo.findByNameNorm("git")).thenReturn(Optional.of(gitVendor));

        when(productRepo.findTop20ByVendorIdAndNameNormStartingWithOrderByNameNormAsc(10L, "git desktop"))
                .thenReturn(List.of(gitDesktop));

        when(productRepo.findTop20ByVendorIdAndNameNormStartingWithOrderByNameNormAsc(10L, "desktop"))
                .thenReturn(List.of());
        when(productRepo.findTop20ByVendorIdAndNameNormContainingOrderByNameNormAsc(10L, "desktop"))
                .thenReturn(List.of());

        when(productRepo.findTop20ByVendorIdAndNameNormStartingWithOrderByNameNormAsc(10L, "git"))
                .thenReturn(List.of());
        when(productRepo.findTop20ByVendorIdAndNameNormContainingOrderByNameNormAsc(10L, "git"))
                .thenReturn(List.of());

        mockMvc.perform(get("/api/dict/products")
                        .param("vendor", "the git")
                        .param("q", "git desktop"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("application/json"))
                .andExpect(jsonPath("$[0].value").value("git_desktop"))
                .andExpect(jsonPath("$[0].label").value("Git Desktop"));

        verify(systemSettingRepository).findById(KEY_CANONICAL_CANDIDATE_MIN_CHARS);
        verify(systemSettingRepository).findById(KEY_CANONICAL_CANDIDATE_OTHER_LIMIT);
        verifyNoMoreInteractions(systemSettingRepository);

        verify(normalizer).normalizeVendor("the git");
        verify(normalizer).normalizeProduct("git desktop");
        verifyNoMoreInteractions(normalizer);

        verify(synonymService).canonicalVendorOrSame("the git");
        verify(synonymService).canonicalVendorOrSame("git");
        verify(synonymService).canonicalProductOrSame("git", "git desktop");
        verify(synonymService).canonicalProductOrSame("git", "desktop");
        verify(synonymService).canonicalProductOrSame("git", "git");
        verifyNoMoreInteractions(synonymService);

        verify(vendorRepo).findByNameNorm("the git");
        verify(vendorRepo).findTop20ByNameNormStartingWithOrderByNameNormAsc("the git");
        verify(vendorRepo).findTop20ByNameNormContainingOrderByNameNormAsc("the git");
        verify(vendorRepo).findByNameNorm("git");
        verifyNoMoreInteractions(vendorRepo);

        verify(productRepo)
                .findTop20ByVendorIdAndNameNormStartingWithOrderByNameNormAsc(10L, "git desktop");
        verify(productRepo)
                .findTop20ByVendorIdAndNameNormStartingWithOrderByNameNormAsc(10L, "desktop");
        verify(productRepo)
                .findTop20ByVendorIdAndNameNormContainingOrderByNameNormAsc(10L, "desktop");
        verify(productRepo)
                .findTop20ByVendorIdAndNameNormStartingWithOrderByNameNormAsc(10L, "git");
        verify(productRepo)
                .findTop20ByVendorIdAndNameNormContainingOrderByNameNormAsc(10L, "git");
        verifyNoMoreInteractions(productRepo);
    }

    // =========================================================
    // Grouped selector UI (/api/dict/vendors/search2, /api/dict/products/search2)
    // =========================================================

    @Test
    @DisplayName("GET /api/dict/vendors/search2 falls back from whole-string miss to token match")
    void searchVendorsByIdGrouped_fallsBackToToken_whenWholeStringDoesNotMatch() throws Exception {

        CpeVendor git = vendor(10L, "git", "Git");
        CpeVendor github = vendor(11L, "github", "GitHub");

        mockIntSetting(KEY_CANONICAL_CANDIDATE_MIN_CHARS, 2);
        mockIntSetting(KEY_CANONICAL_CANDIDATE_EXACT_LIMIT, 5);
        mockIntSetting(KEY_CANONICAL_CANDIDATE_OTHER_LIMIT, 30);

        when(normalizer.normalizeVendor("the git development community"))
                .thenReturn("the git development community");

        when(synonymService.canonicalVendorOrSame("the git development community"))
                .thenReturn("the git development community");
        when(synonymService.canonicalVendorOrSame("git"))
                .thenReturn("git");

        when(vendorRepo.findExact("the git development community")).thenReturn(List.of());
        when(vendorRepo.findPrefixOrderByLength("the git development community")).thenReturn(List.of());
        when(vendorRepo.findContainsOrderByLength("the git development community")).thenReturn(List.of());

        when(vendorRepo.findExact("git")).thenReturn(List.of(git));
        when(vendorRepo.findPrefixOrderByLength("git")).thenReturn(List.of(git, github));
        when(vendorRepo.findContainsOrderByLength("git")).thenReturn(List.of(git, github));

        mockMvc.perform(get("/api/dict/vendors/search2").param("q", "the git development community"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("application/json"))
                .andExpect(jsonPath("$.exact[0].id").value(10))
                .andExpect(jsonPath("$.exact[0].label").value("Git"))
                .andExpect(jsonPath("$.exact[0].nameNorm").value("git"))
                .andExpect(jsonPath("$.others[0].id").value(11))
                .andExpect(jsonPath("$.others[0].label").value("GitHub"))
                .andExpect(jsonPath("$.others[0].nameNorm").value("github"));
    }

    @Test
    @DisplayName("GET /api/dict/products/search2 returns grouped product suggestions under selected vendor")
    void searchProductsByIdGrouped_returnsGroupedSuggestions() throws Exception {

        CpeVendor gitVendor = vendor(10L, "git", "Git");
        CpeProduct gitDesktop = product(101L, gitVendor, "git_desktop", "Git Desktop");
        CpeProduct githubDesktop = product(102L, gitVendor, "github_desktop", "GitHub Desktop");

        mockIntSetting(KEY_CANONICAL_CANDIDATE_MIN_CHARS, 2);
        mockIntSetting(KEY_CANONICAL_CANDIDATE_EXACT_LIMIT, 5);
        mockIntSetting(KEY_CANONICAL_CANDIDATE_OTHER_LIMIT, 30);

        when(vendorRepo.findById(10L)).thenReturn(Optional.of(gitVendor));
        when(normalizer.normalizeProduct("the git desktop")).thenReturn("the git desktop");

        when(synonymService.canonicalProductOrSame("git", "the git desktop")).thenReturn("the git desktop");
        when(synonymService.canonicalProductOrSame("git", "desktop")).thenReturn("desktop");
        when(synonymService.canonicalProductOrSame("git", "git")).thenReturn("git");

        when(productRepo.findExactByVendorId(10L, "the git desktop")).thenReturn(List.of());
        when(productRepo.findTop50ByVendorIdAndNameNormStartingWithOrderByNameNormAsc(10L, "the git desktop"))
                .thenReturn(List.of());
        when(productRepo.findTop50ByVendorIdAndNameNormContainsOrderByNameNormAsc(10L, "the git desktop"))
                .thenReturn(List.of());

        when(productRepo.findExactByVendorId(10L, "desktop")).thenReturn(List.of(gitDesktop));
        when(productRepo.findTop50ByVendorIdAndNameNormStartingWithOrderByNameNormAsc(10L, "desktop"))
                .thenReturn(List.of(gitDesktop, githubDesktop));
        when(productRepo.findTop50ByVendorIdAndNameNormContainsOrderByNameNormAsc(10L, "desktop"))
                .thenReturn(List.of(gitDesktop, githubDesktop));

        mockMvc.perform(get("/api/dict/products/search2")
                        .param("vendorId", "10")
                        .param("q", "the git desktop"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("application/json"))
                .andExpect(jsonPath("$.exact[0].id").value(101))
                .andExpect(jsonPath("$.exact[0].label").value("Git Desktop"))
                .andExpect(jsonPath("$.exact[0].nameNorm").value("git_desktop"))
                .andExpect(jsonPath("$.others[0].id").value(102))
                .andExpect(jsonPath("$.others[0].label").value("GitHub Desktop"))
                .andExpect(jsonPath("$.others[0].nameNorm").value("github_desktop"));
    }

    // =========================================================
    // Edge cases
    // =========================================================

    @Test
    @DisplayName("GET /api/dict/vendors returns empty when query too short")
    void suggestVendors_returnsEmpty_whenTooShort() throws Exception {

        mockIntSetting(KEY_CANONICAL_CANDIDATE_MIN_CHARS, 2);
        mockIntSetting(KEY_CANONICAL_CANDIDATE_OTHER_LIMIT, 30);

        when(normalizer.normalizeVendor("g")).thenReturn("g");

        mockMvc.perform(get("/api/dict/vendors").param("q", "g"))
                .andExpect(status().isOk())
                .andExpect(content().json("[]"));

        verify(systemSettingRepository).findById(KEY_CANONICAL_CANDIDATE_MIN_CHARS);
        verify(systemSettingRepository).findById(KEY_CANONICAL_CANDIDATE_OTHER_LIMIT);

        verify(normalizer).normalizeVendor("g");

        verifyNoInteractions(synonymService, vendorRepo, productRepo);
    }

    @Test
    @DisplayName("GET /api/dict/products returns empty when vendor cannot be resolved")
    void suggestProducts_returnsEmpty_whenVendorCannotBeResolved() throws Exception {

        mockIntSetting(KEY_CANONICAL_CANDIDATE_MIN_CHARS, 2);
        mockIntSetting(KEY_CANONICAL_CANDIDATE_OTHER_LIMIT, 30);

        when(normalizer.normalizeVendor("unknown vendor")).thenReturn("unknown vendor");

        when(synonymService.canonicalVendorOrSame("unknown vendor")).thenReturn("unknown vendor");
        when(synonymService.canonicalVendorOrSame("vendor")).thenReturn("vendor");

        when(vendorRepo.findByNameNorm("unknown vendor")).thenReturn(Optional.empty());
        when(vendorRepo.findTop20ByNameNormStartingWithOrderByNameNormAsc("unknown vendor")).thenReturn(List.of());
        when(vendorRepo.findTop20ByNameNormContainingOrderByNameNormAsc("unknown vendor")).thenReturn(List.of());

        when(vendorRepo.findByNameNorm("vendor")).thenReturn(Optional.empty());
        when(vendorRepo.findTop20ByNameNormStartingWithOrderByNameNormAsc("vendor")).thenReturn(List.of());
        when(vendorRepo.findTop20ByNameNormContainingOrderByNameNormAsc("vendor")).thenReturn(List.of());

        mockMvc.perform(get("/api/dict/products")
                        .param("vendor", "unknown vendor")
                        .param("q", "desktop"))
                .andExpect(status().isOk())
                .andExpect(content().json("[]"));

        verifyNoInteractions(productRepo);
    }

    @Test
    @DisplayName("GET /api/dict/vendors/search2 returns empty when query too short")
    void searchVendorsByIdGrouped_returnsEmpty_whenTooShort() throws Exception {

        mockIntSetting(KEY_CANONICAL_CANDIDATE_MIN_CHARS, 2);
        mockIntSetting(KEY_CANONICAL_CANDIDATE_EXACT_LIMIT, 5);
        mockIntSetting(KEY_CANONICAL_CANDIDATE_OTHER_LIMIT, 30);

        when(normalizer.normalizeVendor("g")).thenReturn("g");

        mockMvc.perform(get("/api/dict/vendors/search2").param("q", "g"))
                .andExpect(status().isOk())
                .andExpect(content().json("{\"exact\":[],\"others\":[]}"));
    }

    @Test
    @DisplayName("GET /api/dict/products/search2 returns empty when vendorId does not exist")
    void searchProductsByIdGrouped_returnsEmpty_whenVendorMissing() throws Exception {

        mockIntSetting(KEY_CANONICAL_CANDIDATE_MIN_CHARS, 2);
        mockIntSetting(KEY_CANONICAL_CANDIDATE_EXACT_LIMIT, 5);
        mockIntSetting(KEY_CANONICAL_CANDIDATE_OTHER_LIMIT, 30);

        when(vendorRepo.findById(999L)).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/dict/products/search2")
                        .param("vendorId", "999")
                        .param("q", "desktop"))
                .andExpect(status().isOk())
                .andExpect(content().json("{\"exact\":[],\"others\":[]}"));

        verifyNoInteractions(productRepo, synonymService, normalizer);
    }

    // =========================================================
    // Helpers
    // =========================================================

    private void mockIntSetting(String key, int value) {
        SystemSetting setting = SystemSetting.of(key, String.valueOf(value), "test");
        when(systemSettingRepository.findById(key)).thenReturn(Optional.of(setting));
    }

    private static CpeVendor vendor(Long id, String nameNorm, String displayName) {
        CpeVendor v = new CpeVendor(nameNorm, displayName);
        setId(v, id);
        return v;
    }

    private static CpeProduct product(Long id, CpeVendor vendor, String nameNorm, String displayName) {
        CpeProduct p = new CpeProduct(vendor, nameNorm, displayName);
        setId(p, id);
        return p;
    }

    private static void setId(Object target, Long id) {
        try {
            var field = target.getClass().getDeclaredField("id");
            field.setAccessible(true);
            field.set(target, id);
        } catch (Exception e) {
            throw new RuntimeException("Failed to set id for test object: " + target.getClass().getSimpleName(), e);
        }
    }
}