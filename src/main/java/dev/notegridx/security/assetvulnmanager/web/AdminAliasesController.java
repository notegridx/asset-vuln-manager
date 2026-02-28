package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.CpeProductAlias;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendorAlias;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductAliasRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorAliasRepository;
import dev.notegridx.security.assetvulnmanager.service.CanonicalBackfillService;
import dev.notegridx.security.assetvulnmanager.service.SynonymService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AdminAliasesController {

    private final CpeVendorAliasRepository vendorAliasRepo;
    private final CpeProductAliasRepository productAliasRepo;
    private final CanonicalBackfillService backfillService;
    private final SynonymService synonymService;

    public AdminAliasesController(
            CpeVendorAliasRepository vendorAliasRepo,
            CpeProductAliasRepository productAliasRepo,
            CanonicalBackfillService backfillService,
            SynonymService synonymService
    ) {
        this.vendorAliasRepo = vendorAliasRepo;
        this.productAliasRepo = productAliasRepo;
        this.backfillService = backfillService;
        this.synonymService = synonymService;
    }

    @PostMapping("/admin/aliases/vendor")
    public String addVendorAlias(
            @RequestParam("aliasNorm") String aliasNorm,
            @RequestParam("cpeVendorId") Long cpeVendorId,
            @RequestParam(value = "note", required = false) String note
    ) {
        vendorAliasRepo.save(new CpeVendorAlias(aliasNorm.trim(), cpeVendorId, note));
        synonymService.clearCaches();
        backfillService.backfill(5_000_000, false);
        return "redirect:/admin/unresolved?status=NEW";
    }

    @PostMapping("/admin/aliases/product")
    public String addProductAlias(
            @RequestParam("cpeVendorId") Long cpeVendorId,
            @RequestParam("aliasNorm") String aliasNorm,
            @RequestParam("cpeProductId") Long cpeProductId,
            @RequestParam(value = "note", required = false) String note
    ) {
        productAliasRepo.save(new CpeProductAlias(cpeVendorId, aliasNorm.trim(), cpeProductId, note));
        synonymService.clearCaches();
        backfillService.backfill(5_000_000, false);
        return "redirect:/admin/unresolved?status=NEW";
    }
}