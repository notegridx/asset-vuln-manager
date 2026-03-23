package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.CpeProductAlias;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendorAlias;
import dev.notegridx.security.assetvulnmanager.domain.enums.AliasReviewState;
import dev.notegridx.security.assetvulnmanager.domain.enums.AliasSource;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductAliasRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorAliasRepository;
import dev.notegridx.security.assetvulnmanager.service.AliasBatchService;
import dev.notegridx.security.assetvulnmanager.service.CanonicalBackfillService;
import dev.notegridx.security.assetvulnmanager.service.DemoModeService;
import dev.notegridx.security.assetvulnmanager.service.SynonymService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class AdminAliasesController {

    private static final int DEFAULT_MANUAL_CONFIDENCE = 80; // 0..100

    private final CpeVendorAliasRepository vendorAliasRepo;
    private final CpeProductAliasRepository productAliasRepo;
    private final CanonicalBackfillService backfillService;
    private final SynonymService synonymService;
    private final AliasBatchService aliasBatchService;
    private final DemoModeService demoModeService;

    public AdminAliasesController(
            CpeVendorAliasRepository vendorAliasRepo,
            CpeProductAliasRepository productAliasRepo,
            CanonicalBackfillService backfillService,
            SynonymService synonymService,
            AliasBatchService aliasBatchService,
            DemoModeService demoModeService
    ) {
        this.vendorAliasRepo = vendorAliasRepo;
        this.productAliasRepo = productAliasRepo;
        this.backfillService = backfillService;
        this.synonymService = synonymService;
        this.aliasBatchService = aliasBatchService;
        this.demoModeService = demoModeService;
    }

    @PostMapping("/admin/aliases/vendor")
    public String addVendorAlias(
            @RequestParam("aliasNorm") String aliasNorm,
            @RequestParam("cpeVendorId") Long cpeVendorId,
            @RequestParam(value = "note", required = false) String note,
            @RequestParam(name = "redirect", required = false) String redirect
    ) {
        demoModeService.assertWritable();

        String a = normalize(aliasNorm);
        if (a == null) {
            return safeRedirectOrDefault(redirect, "/admin/unresolved?status=NEW");
        }

        CpeVendorAlias entity = CpeVendorAlias.seeded(
                cpeVendorId,
                a,
                note,
                AliasSource.MANUAL,
                AliasReviewState.MANUAL,
                DEFAULT_MANUAL_CONFIDENCE,
                null
        );

        vendorAliasRepo.save(entity);
        synonymService.clearCaches();

        return safeRedirectOrDefault(redirect, "/admin/unresolved?status=NEW");
    }

    @PostMapping("/admin/aliases/product")
    public String addProductAlias(
            @RequestParam("cpeVendorId") Long cpeVendorId,
            @RequestParam("aliasNorm") String aliasNorm,
            @RequestParam("cpeProductId") Long cpeProductId,
            @RequestParam(value = "note", required = false) String note,
            @RequestParam(name = "redirect", required = false) String redirect
    ) {
        demoModeService.assertWritable();

        String a = normalize(aliasNorm);
        if (a == null) {
            return safeRedirectOrDefault(redirect, "/admin/unresolved?status=NEW");
        }

        CpeProductAlias entity = CpeProductAlias.seeded(
                cpeVendorId,
                cpeProductId,
                a,
                note,
                AliasSource.MANUAL,
                AliasReviewState.MANUAL,
                DEFAULT_MANUAL_CONFIDENCE,
                null
        );

        productAliasRepo.save(entity);
        synonymService.clearCaches();

        return safeRedirectOrDefault(redirect, "/admin/unresolved?status=NEW");
    }

    @PostMapping("/admin/aliases/seed-top")
    public String seedTopAliases(
            @RequestParam(name = "redirect", required = false) String redirect,
            RedirectAttributes ra
    ) {
        demoModeService.assertWritable();

        AliasBatchService.BatchReport report = aliasBatchService.seedTopAliases();
        ra.addFlashAttribute("seedReport", report);

        return safeRedirectOrDefault(redirect, "/admin/synonyms/vendors");
    }

    @PostMapping("/admin/aliases/delete-all")
    public String deleteAllAliases(
            @RequestParam(name = "redirect", required = false) String redirect,
            RedirectAttributes ra
    ) {
        demoModeService.assertWritable();

        long vendorAliasCount = vendorAliasRepo.count();
        long productAliasCount = productAliasRepo.count();

        productAliasRepo.deleteAll();
        vendorAliasRepo.deleteAll();
        synonymService.clearCaches();

        ra.addFlashAttribute(
                "message",
                "Deleted all aliases. vendorAliases=" + vendorAliasCount + ", productAliases=" + productAliasCount
        );

        return safeRedirectOrDefault(redirect, "/admin/synonyms/workspace");
    }

    // Keep existing normalization behavior for manual alias input.
    private static String normalize(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    // Allow only application-local redirects and fall back safely.
    private static String safeRedirectOrDefault(String redirect, String fallback) {
        if (redirect == null || redirect.isBlank()) return "redirect:" + fallback;
        // assume redirect is already "redirect:/..." or "/..."
        if (redirect.startsWith("redirect:")) return redirect;
        if (redirect.startsWith("/")) return "redirect:" + redirect;
        return "redirect:" + fallback;
    }
}