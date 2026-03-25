package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.CpeProduct;
import dev.notegridx.security.assetvulnmanager.domain.CpeProductAlias;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendor;
import dev.notegridx.security.assetvulnmanager.domain.CpeVendorAlias;
import dev.notegridx.security.assetvulnmanager.domain.enums.AliasReviewState;
import dev.notegridx.security.assetvulnmanager.domain.enums.AliasSource;
import dev.notegridx.security.assetvulnmanager.repository.CpeProductAliasRepository;
import dev.notegridx.security.assetvulnmanager.repository.CpeVendorAliasRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.TypedQuery;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class AliasBatchService {

    private static final Logger log = LoggerFactory.getLogger(AliasBatchService.class);

    private final CpeVendorAliasRepository vendorAliasRepository;
    private final CpeProductAliasRepository productAliasRepository;
    private final SynonymService synonymService;

    @PersistenceContext
    private EntityManager em;

    public AliasBatchService(
            CpeVendorAliasRepository vendorAliasRepository,
            CpeProductAliasRepository productAliasRepository,
            SynonymService synonymService
    ) {
        this.vendorAliasRepository = vendorAliasRepository;
        this.productAliasRepository = productAliasRepository;
        this.synonymService = synonymService;
    }

    // =========================================================
    // Public API
    // =========================================================

    @Transactional
    public BatchReport seedTopAliases() {
        // Treat the auto-seeded Top20 set as confirmed entries.
        AliasSource source = AliasSource.MANUAL;      // No dedicated enum exists for Top20 seeding, so this is selected operationally.
        AliasReviewState review = AliasReviewState.AUTO;

        List<VendorSeed> vendors = defaultTopVendorSeeds();
        List<ProductSeed> products = defaultTopProductSeeds();

        BatchReport report = new BatchReport("seedTopAliases");

        // ---------- Vendors ----------
        for (VendorSeed s : vendors) {
            Optional<CpeVendor> v = findVendorByNameNorm(s.canonicalVendorNorm);
            if (v.isEmpty()) {
                report.vendorSkipped++;
                report.messages.add("SKIP vendor: dictionary missing name_norm=" + s.canonicalVendorNorm);
                continue;
            }

            UpsertResult r = upsertVendorAlias(
                    s.aliasNorm,
                    v.get().getId(),
                    s.note,
                    source,
                    review,
                    s.confidence,
                    s.evidenceUrl
            );
            report.addVendor(r);
        }

        // ---------- Products ----------
        for (ProductSeed s : products) {
            Optional<CpeVendor> v = findVendorByNameNorm(s.canonicalVendorNorm);
            if (v.isEmpty()) {
                report.productSkipped++;
                report.messages.add("SKIP product: vendor missing name_norm=" + s.canonicalVendorNorm);
                continue;
            }

            Optional<CpeProduct> p = findProductByVendorIdAndNameNorm(v.get().getId(), s.canonicalProductNorm);
            if (p.isEmpty()) {
                report.productSkipped++;
                report.messages.add("SKIP product: dictionary missing vendor=" + s.canonicalVendorNorm
                        + " product=" + s.canonicalProductNorm);
                continue;
            }

            UpsertResult r = upsertProductAlias(
                    v.get().getId(),
                    s.aliasNorm,
                    p.get().getId(),
                    s.note,
                    source,
                    review,
                    s.confidence,
                    s.evidenceUrl
            );
            report.addProduct(r);
        }

        synonymService.clearCaches();

        log.info("AliasBatchService {} done. {}", report.batchName, report.toLogString());
        for (String m : report.messages) log.info("  {}", m);

        return report;
    }

    // =========================================================
    // Upserts
    // =========================================================

    @Transactional
    public UpsertResult upsertVendorAlias(
            String aliasNorm,
            Long cpeVendorId,
            String note,
            AliasSource source,
            AliasReviewState reviewState,
            Integer confidence,
            String evidenceUrl
    ) {
        String a = safeNorm(aliasNorm);
        if (a == null) return UpsertResult.skipped("vendor aliasNorm is blank");

        Optional<CpeVendorAlias> existing = findVendorAliasByAliasNorm(a);

        if (existing.isPresent()) {
            CpeVendorAlias row = existing.get();
            boolean changed = false;

            // Skip when the alias already points to a different vendor.
            // This avoids accidental remapping and there is no direct setter-based remap path here.
            if (!cpeVendorId.equals(row.getCpeVendorId())) {
                return UpsertResult.skipped("vendor alias exists with different cpeVendorId. alias=" + a
                        + " existing=" + row.getCpeVendorId() + " new=" + cpeVendorId);
            }

            if (note != null && !note.equals(row.getNote())) {
                row.setNote(note);
                changed = true;
            }

            if (!CpeVendorAlias.STATUS_ACTIVE.equals(row.getStatus())) {
                row.setStatus(CpeVendorAlias.STATUS_ACTIVE);
                changed = true;
            }

            if (source != null && source != row.getSource()) {
                row.setSource(source);
                changed = true;
            }
            if (reviewState != null && reviewState != row.getReviewState()) {
                row.setReviewState(reviewState);
                changed = true;
            }

            Integer rowConf = row.getConfidence();
            if (confidence != null && (rowConf == null || !confidence.equals(rowConf))) {
                row.setConfidence(confidence);
                changed = true;
            }

            if (evidenceUrl != null && (row.getEvidenceUrl() == null || !evidenceUrl.equals(row.getEvidenceUrl()))) {
                row.setEvidenceUrl(evidenceUrl);
                changed = true;
            }

            if (changed) {
                vendorAliasRepository.save(row);
                return UpsertResult.updated("vendor alias updated. alias=" + a);
            }
            return UpsertResult.unchanged("vendor alias unchanged. alias=" + a);
        }

        // Use the seeded factory instead of new to keep argument ordering consistent.
        CpeVendorAlias created = CpeVendorAlias.seeded(
                cpeVendorId,
                a,
                note,
                source,
                reviewState,
                confidence,
                evidenceUrl
        );

        vendorAliasRepository.save(created);
        return UpsertResult.inserted("vendor alias inserted. alias=" + a);
    }

    @Transactional
    public UpsertResult upsertProductAlias(
            Long cpeVendorId,
            String aliasNorm,
            Long cpeProductId,
            String note,
            AliasSource source,
            AliasReviewState reviewState,
            Integer confidence,
            String evidenceUrl
    ) {
        String a = safeNorm(aliasNorm);
        if (a == null) return UpsertResult.skipped("product aliasNorm is blank");

        Optional<CpeProductAlias> existing = findProductAliasByVendorIdAndAliasNorm(cpeVendorId, a);

        if (existing.isPresent()) {
            CpeProductAlias row = existing.get();
            boolean changed = false;

            // Skip when the alias already points to a different product under the same vendor.
            if (!cpeProductId.equals(row.getCpeProductId())) {
                return UpsertResult.skipped("product alias exists with different cpeProductId. vendorId=" + cpeVendorId
                        + " alias=" + a + " existing=" + row.getCpeProductId() + " new=" + cpeProductId);
            }

            if (note != null && !note.equals(row.getNote())) {
                row.setNote(note);
                changed = true;
            }

            if (!CpeProductAlias.STATUS_ACTIVE.equals(row.getStatus())) {
                row.setStatus(CpeProductAlias.STATUS_ACTIVE);
                changed = true;
            }

            if (source != null && source != row.getSource()) {
                row.setSource(source);
                changed = true;
            }
            if (reviewState != null && reviewState != row.getReviewState()) {
                row.setReviewState(reviewState);
                changed = true;
            }

            Integer rowConf = row.getConfidence();
            if (confidence != null && (rowConf == null || !confidence.equals(rowConf))) {
                row.setConfidence(confidence);
                changed = true;
            }

            if (evidenceUrl != null && (row.getEvidenceUrl() == null || !evidenceUrl.equals(row.getEvidenceUrl()))) {
                row.setEvidenceUrl(evidenceUrl);
                changed = true;
            }

            if (changed) {
                productAliasRepository.save(row);
                return UpsertResult.updated("product alias updated. vendorId=" + cpeVendorId + " alias=" + a);
            }
            return UpsertResult.unchanged("product alias unchanged. vendorId=" + cpeVendorId + " alias=" + a);
        }

        // Use the seeded factory instead of new to keep argument ordering consistent.
        CpeProductAlias created = CpeProductAlias.seeded(
                cpeVendorId,
                cpeProductId,
                a,
                note,
                source,
                reviewState,
                confidence,
                evidenceUrl
        );

        productAliasRepository.save(created);
        return UpsertResult.inserted("product alias inserted. vendorId=" + cpeVendorId + " alias=" + a);
    }

    // =========================================================
    // Lookups (EntityManager; no repo custom finders required)
    // =========================================================

    private Optional<CpeVendor> findVendorByNameNorm(String nameNorm) {
        if (nameNorm == null || nameNorm.trim().isEmpty()) return Optional.empty();
        TypedQuery<CpeVendor> q = em.createQuery(
                "select v from CpeVendor v where v.nameNorm = :n", CpeVendor.class);
        q.setParameter("n", nameNorm.trim());
        q.setMaxResults(1);
        List<CpeVendor> rows = q.getResultList();
        return rows.isEmpty() ? Optional.empty() : Optional.of(rows.get(0));
    }

    private Optional<CpeProduct> findProductByVendorIdAndNameNorm(Long vendorId, String productNorm) {
        if (vendorId == null) return Optional.empty();
        if (productNorm == null || productNorm.trim().isEmpty()) return Optional.empty();
        TypedQuery<CpeProduct> q = em.createQuery(
                "select p from CpeProduct p where p.vendor.id = :vid and p.nameNorm = :pn", CpeProduct.class);
        q.setParameter("vid", vendorId);
        q.setParameter("pn", productNorm.trim());
        q.setMaxResults(1);
        List<CpeProduct> rows = q.getResultList();
        return rows.isEmpty() ? Optional.empty() : Optional.of(rows.get(0));
    }

    private Optional<CpeVendorAlias> findVendorAliasByAliasNorm(String aliasNorm) {
        TypedQuery<CpeVendorAlias> q = em.createQuery(
                "select a from CpeVendorAlias a where a.aliasNorm = :an", CpeVendorAlias.class);
        q.setParameter("an", aliasNorm);
        q.setMaxResults(1);
        List<CpeVendorAlias> rows = q.getResultList();
        return rows.isEmpty() ? Optional.empty() : Optional.of(rows.get(0));
    }

    private Optional<CpeProductAlias> findProductAliasByVendorIdAndAliasNorm(Long vendorId, String aliasNorm) {
        TypedQuery<CpeProductAlias> q = em.createQuery(
                "select a from CpeProductAlias a where a.cpeVendorId = :vid and a.aliasNorm = :an",
                CpeProductAlias.class);
        q.setParameter("vid", vendorId);
        q.setParameter("an", aliasNorm);
        q.setMaxResults(1);
        List<CpeProductAlias> rows = q.getResultList();
        return rows.isEmpty() ? Optional.empty() : Optional.of(rows.get(0));
    }

    private String safeNorm(String s) {
        if (s == null) return null;
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    // =========================================================
    // Seed data (replace with your curated list)
    // =========================================================

    private List<VendorSeed> defaultTopVendorSeeds() {
        List<VendorSeed> xs = new ArrayList<>();

        xs.add(VendorSeed.of("microsoft", "microsoft", "Common vendor alias", 98, null));
        xs.add(VendorSeed.of("ms", "microsoft", "Abbrev", 85, null));
        xs.add(VendorSeed.of("google", "google", "Common vendor alias", 98, null));
        xs.add(VendorSeed.of("alphabet", "google", "Parent company name", 70, null));
        xs.add(VendorSeed.of("apple", "apple", "Common vendor alias", 98, null));
        xs.add(VendorSeed.of("adobe", "adobe", "Common vendor alias", 98, null));
        xs.add(VendorSeed.of("oracle", "oracle", "Common vendor alias", 98, null));
        xs.add(VendorSeed.of("cisco", "cisco", "Common vendor alias", 98, null));
        xs.add(VendorSeed.of("vmware", "vmware", "Common vendor alias", 98, null));
        xs.add(VendorSeed.of("apache", "apache", "Common vendor alias", 95, null));
        xs.add(VendorSeed.of("mozilla", "mozilla", "Common vendor alias", 95, null));
        xs.add(VendorSeed.of("redhat", "redhat", "Common vendor alias", 95, null));
        xs.add(VendorSeed.of("ibm", "ibm", "Common vendor alias", 95, null));
        xs.add(VendorSeed.of("dell", "dell", "Common vendor alias", 95, null));
        xs.add(VendorSeed.of("hp", "hp", "Common vendor alias", 95, null));
        xs.add(VendorSeed.of("hewlettpackard", "hp", "Spelling variant", 80, null));
        xs.add(VendorSeed.of("intel", "intel", "Common vendor alias", 95, null));
        xs.add(VendorSeed.of("nvidia", "nvidia", "Common vendor alias", 95, null));
        xs.add(VendorSeed.of("docker", "docker", "Common vendor alias", 90, null));
        xs.add(VendorSeed.of("kubernetes", "kubernetes", "Project name as vendor", 70, null));

        return xs;
    }

    private List<ProductSeed> defaultTopProductSeeds() {
        List<ProductSeed> xs = new ArrayList<>();

        xs.add(ProductSeed.of("microsoft", "windows", "windows", "Common", 98, null));
        xs.add(ProductSeed.of("microsoft", "office", "office", "Common", 95, null));
        xs.add(ProductSeed.of("microsoft", "edge", "edge", "Browser", 95, null));
        xs.add(ProductSeed.of("microsoft", "exchange", "exchange_server", "Mail server", 90, null));

        xs.add(ProductSeed.of("google", "chrome", "chrome", "Browser", 98, null));

        xs.add(ProductSeed.of("apple", "macos", "mac_os", "OS naming", 80, null));
        xs.add(ProductSeed.of("apple", "ios", "iphone_os", "OS naming", 80, null));
        xs.add(ProductSeed.of("apple", "safari", "safari", "Browser", 90, null));

        xs.add(ProductSeed.of("adobe", "acrobat", "acrobat_reader", "PDF", 85, null));
        xs.add(ProductSeed.of("adobe", "reader", "acrobat_reader", "PDF", 80, null));

        xs.add(ProductSeed.of("vmware", "vcenter", "vcenter_server", "Management", 85, null));
        xs.add(ProductSeed.of("vmware", "esxi", "esxi", "Hypervisor", 90, null));

        xs.add(ProductSeed.of("cisco", "iosxe", "ios_xe", "Network OS", 85, null));
        xs.add(ProductSeed.of("cisco", "asa", "adaptive_security_appliance", "Firewall", 80, null));

        return xs;
    }

    // =========================================================
    // DTOs / report
    // =========================================================

    public static class BatchReport {
        public final String batchName;

        public int vendorInserted;
        public int vendorUpdated;
        public int vendorUnchanged;
        public int vendorSkipped;

        public int productInserted;
        public int productUpdated;
        public int productUnchanged;
        public int productSkipped;

        public final List<String> messages = new ArrayList<>();

        public BatchReport(String batchName) {
            this.batchName = batchName;
        }

        void addVendor(UpsertResult r) {
            switch (r.kind) {
                case INSERTED -> vendorInserted++;
                case UPDATED -> vendorUpdated++;
                case UNCHANGED -> vendorUnchanged++;
                case SKIPPED -> vendorSkipped++;
            }
            if (r.message != null) messages.add(r.message);
        }

        void addProduct(UpsertResult r) {
            switch (r.kind) {
                case INSERTED -> productInserted++;
                case UPDATED -> productUpdated++;
                case UNCHANGED -> productUnchanged++;
                case SKIPPED -> productSkipped++;
            }
            if (r.message != null) messages.add(r.message);
        }

        public String toLogString() {
            return "vendors={ins=" + vendorInserted + ",upd=" + vendorUpdated + ",same=" + vendorUnchanged + ",skip=" + vendorSkipped + "}, "
                    + "products={ins=" + productInserted + ",upd=" + productUpdated + ",same=" + productUnchanged + ",skip=" + productSkipped + "}";
        }
    }

    public static class UpsertResult {
        public enum Kind { INSERTED, UPDATED, UNCHANGED, SKIPPED }

        public final Kind kind;
        public final String message;

        private UpsertResult(Kind kind, String message) {
            this.kind = kind;
            this.message = message;
        }

        public static UpsertResult inserted(String msg) { return new UpsertResult(Kind.INSERTED, msg); }
        public static UpsertResult updated(String msg) { return new UpsertResult(Kind.UPDATED, msg); }
        public static UpsertResult unchanged(String msg) { return new UpsertResult(Kind.UNCHANGED, msg); }
        public static UpsertResult skipped(String msg) { return new UpsertResult(Kind.SKIPPED, msg); }
    }

    private static class VendorSeed {
        final String aliasNorm;
        final String canonicalVendorNorm;
        final String note;
        final Integer confidence;
        final String evidenceUrl;

        private VendorSeed(String aliasNorm, String canonicalVendorNorm, String note, Integer confidence, String evidenceUrl) {
            this.aliasNorm = aliasNorm;
            this.canonicalVendorNorm = canonicalVendorNorm;
            this.note = note;
            this.confidence = confidence;
            this.evidenceUrl = evidenceUrl;
        }

        static VendorSeed of(String aliasNorm, String canonicalVendorNorm, String note, Integer confidence, String evidenceUrl) {
            return new VendorSeed(aliasNorm, canonicalVendorNorm, note, confidence, evidenceUrl);
        }
    }

    private static class ProductSeed {
        final String canonicalVendorNorm;
        final String aliasNorm;
        final String canonicalProductNorm;
        final String note;
        final Integer confidence;
        final String evidenceUrl;

        private ProductSeed(String canonicalVendorNorm,
                            String aliasNorm,
                            String canonicalProductNorm,
                            String note,
                            Integer confidence,
                            String evidenceUrl) {
            this.canonicalVendorNorm = canonicalVendorNorm;
            this.aliasNorm = aliasNorm;
            this.canonicalProductNorm = canonicalProductNorm;
            this.note = note;
            this.confidence = confidence;
            this.evidenceUrl = evidenceUrl;
        }

        static ProductSeed of(String canonicalVendorNorm,
                              String aliasNorm,
                              String canonicalProductNorm,
                              String note,
                              Integer confidence,
                              String evidenceUrl) {
            return new ProductSeed(canonicalVendorNorm, aliasNorm, canonicalProductNorm, note, confidence, evidenceUrl);
        }
    }
}