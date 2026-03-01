package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.CpeProductAlias;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendorAlias;
import dev.notegridx.security.assetvulnmanager.domain.enums.AliasReviewState;
import dev.notegridx.security.assetvulnmanager.domain.enums.AliasSource;
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

    /**
     * vendor alias 追加：保存 + キャッシュクリアのみ（backfillは別ボタンに分離）
     */
    @PostMapping("/admin/aliases/vendor")
    public String addVendorAlias(
            @RequestParam("aliasNorm") String aliasNorm,
            @RequestParam("cpeVendorId") Long cpeVendorId,
            @RequestParam(value = "note", required = false) String note
    ) {
        String a = normalize(aliasNorm);
        if (a == null) {
            // 入力が空の場合は何もしない（現状のUXを崩したくなければ redirect は同じ）
            return "redirect:/admin/unresolved?status=NEW";
        }

        // ✅ factory/seeded に統一（コンストラクタ順に依存しない）
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
        return "redirect:/admin/unresolved?status=NEW";
    }

    /**
     * product alias 追加：保存 + キャッシュクリアのみ（backfillは別ボタンに分離）
     */
    @PostMapping("/admin/aliases/product")
    public String addProductAlias(
            @RequestParam("cpeVendorId") Long cpeVendorId,
            @RequestParam("aliasNorm") String aliasNorm,
            @RequestParam("cpeProductId") Long cpeProductId,
            @RequestParam(value = "note", required = false) String note
    ) {
        String a = normalize(aliasNorm);
        if (a == null) {
            return "redirect:/admin/unresolved?status=NEW";
        }

        // ✅ factory/seeded に統一（コンストラクタ順に依存しない）
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
        return "redirect:/admin/unresolved?status=NEW";
    }

    /**
     * Canonical backfill を単独実行（どの画面からでも呼べるように redirect を受ける）
     */
    @PostMapping("/admin/canonical/backfill")
    public String runCanonicalBackfill(
            @RequestParam(name = "maxRows", defaultValue = "5000000") int maxRows,
            @RequestParam(name = "forceRebuild", defaultValue = "false") boolean forceRebuild,
            @RequestParam(name = "redirect", required = false) String redirect
    ) {
        synonymService.clearCaches();
        backfillService.backfill(maxRows, forceRebuild);

        if (redirect != null && redirect.startsWith("/")) {
            return "redirect:" + redirect;
        }
        return "redirect:/admin/unresolved?status=NEW";
    }

    private String normalize(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }
}