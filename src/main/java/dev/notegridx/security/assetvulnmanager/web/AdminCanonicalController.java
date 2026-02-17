package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.service.CanonicalCpeLinkingService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AdminCanonicalController {

    private final SoftwareInstallRepository softwareRepo;
    private final CanonicalCpeLinkingService linker;

    public AdminCanonicalController(SoftwareInstallRepository softwareRepo, CanonicalCpeLinkingService linker) {
        this.softwareRepo = softwareRepo;
        this.linker = linker;
    }

    @GetMapping("/admin/canonical")
    public String view(Model model) {
        var installs = softwareRepo.findByAssetIdOrderByIdDesc(1L);

        var rows = installs.stream()
                .limit(200)
                .map(s -> new Row(s.getId(), s.getVendor(), s.getProduct(), s.getVersion(),
                        s.getNormalizedVendor(), s.getNormalizedProduct(),
                        linker.resolve(s)))
                .toList();

        model.addAttribute("rows", rows);
        model.addAttribute("summary", linker.dryLinkSummary(1000));
        return "admin/canonical";
    }

    public record Row(
            Long softwareId,
            String vendor,
            String product,
            String version,
            String normalizedVendor,
            String normalizedProduct,
            CanonicalCpeLinkingService.ResolveResult resolve
    ) {}
}
