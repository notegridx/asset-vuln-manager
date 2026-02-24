package dev.notegridx.security.assetvulnmanager.web;

import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.AlertRepository;
import dev.notegridx.security.assetvulnmanager.repository.AssetRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@Controller
public class SoftwareListController {

    private final SoftwareInstallRepository softwareInstallRepository;
    private final AssetRepository assetRepository;
    private final AlertRepository alertRepository;

    public SoftwareListController(
            SoftwareInstallRepository softwareInstallRepository,
            AssetRepository assetRepository,
            AlertRepository alertRepository
    ) {
        this.softwareInstallRepository = softwareInstallRepository;
        this.assetRepository = assetRepository;
        this.alertRepository = alertRepository;
    }

    @GetMapping("/software")
    public String list(
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "100") int size,
            @RequestParam(name = "assetId", required = false) Long assetId,
            @RequestParam(name = "q", required = false) String q,
            @RequestParam(name = "unmappedCpe", required = false) Boolean unmappedCpe,
            Model model
    ) {
        int safePage = Math.max(0, page);
        int safeSize = clamp(size, 10, 500);

        Pageable pageable = PageRequest.of(safePage, safeSize);
        Page<SoftwareInstall> result =
                softwareInstallRepository.searchPaged(assetId, q, unmappedCpe, pageable);        List<Long> ids = result.getContent()
                .stream()
                .map(SoftwareInstall::getId)
                .toList();

        Map<Long, Long> alertCountMap = new HashMap<>();

        if (!ids.isEmpty()) {
            for (Object[] row : alertRepository.countBySoftwareInstallIds(ids)) {
                Long softwareId = (Long) row[0];
                Long count = (Long) row[1];
                alertCountMap.put(softwareId, count);
            }
        }

        model.addAttribute("alertCountMap", alertCountMap);

        model.addAttribute("page", result);

        // filter state
        model.addAttribute("assetId", assetId);
        model.addAttribute("q", q == null ? "" : q);
        model.addAttribute("unmappedCpe", unmappedCpe);

        // asset dropdown
        model.addAttribute("assets", assetRepository.findAll());

        // counts (optional but useful)
        model.addAttribute("totalInstalls", softwareInstallRepository.count());
        model.addAttribute("unmappedCount", softwareInstallRepository.countUnmappedCpe());



        return "software/list";
    }

    private static int clamp(int v, int min, int max) {
        if (v < min) return min;
        if (v > max) return max;
        return v;
    }
}