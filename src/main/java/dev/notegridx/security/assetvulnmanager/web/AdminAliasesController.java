package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.CpeProductAlias;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendorAlias;
import dev.notegridx.security.assetvulnmanager.domain.enums.AliasReviewState;
import dev.notegridx.security.assetvulnmanager.domain.enums.AliasSource;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductAliasRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorAliasRepository;
import dev.notegridx.security.assetvulnmanager.service.AliasBatchService;
import dev.notegridx.security.assetvulnmanager.service.CanonicalBackfillService;
import dev.notegridx.security.assetvulnmanager.service.SynonymService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class AdminAliasesController {

    private final CpeVendorAliasRepository vendorAliasRepo;
    private final CpeProductAliasRepository productAliasRepo;
    private final CanonicalBackfillService backfillService;
    private final SynonymService synonymService;
    private final AliasBatchService aliasBatchService;

    public AdminAliasesController(
            CpeVendorAliasRepository vendorAliasRepo,
            CpeProductAliasRepository productAliasRepo,
            CanonicalBackfillService backfillService,
            SynonymService synonymService,
            AliasBatchService aliasBatchService
    ) {
        this.vendorAliasRepo = vendorAliasRepo;
        this.productAliasRepo = productAliasRepo;
        this.backfillService = backfillService;
        this.synonymService = synonymService;
        this.aliasBatchService = aliasBatchService;
    }

    @PostMapping("/admin/aliases/vendor")
    public String addVendorAlias(
            @RequestParam("aliasNorm") String aliasNorm,
            @RequestParam("cpeVendorId") Long cpeVendorId,
            @RequestParam(value = "note", required = false) String note,
            @RequestParam(name = "redirect", required = false) String redirect
    ) {
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
                null,
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
                null,
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
        AliasBatchService.BatchReport report = aliasBatchService.seedTopAliases();
        ra.addFlashAttribute("seedReport", report);

        return safeRedirectOrDefault(redirect, "/admin/synonyms/vendors");
    }

    @PostMapping("/admin/canonical/backfill")
    public String runCanonicalBackfill(
            @RequestParam(name = "maxRows", defaultValue = "5000000") int maxRows,
            @RequestParam(name = "forceRebuild", defaultValue = "false") boolean forceRebuild,
            @RequestParam(name = "redirect", required = false) String redirect
    ) {
        synonymService.clearCaches();
        backfillService.backfill(maxRows, forceRebuild);

        return safeRedirectOrDefault(redirect, "/admin/unresolved?status=NEW");
    }

    private String normalize(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static String safeRedirectOrDefault(String redirect, String defaultPath) {
        if (redirect != null && redirect.startsWith("/")) {
            return "redirect:" + redirect;
        }
        return "redirect:" + defaultPath;
    }
}