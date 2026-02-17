package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import jakarta.persistence.EntityManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;

@Service
public class CanonicalBackfillService {

    private static final Logger log = LoggerFactory.getLogger(CanonicalBackfillService.class);

    private static final int TX_CHUNK = 5_000;
    private static final int LOG_EVERY = 10_000;
    private static final int FLUSH_EVERY = 2_000;

    private final SoftwareInstallRepository softwareRepo;
    private final CanonicalCpeLinkingService linker;
    private final EntityManager em;
    private final TransactionTemplate chunkTx;

    public CanonicalBackfillService(
            SoftwareInstallRepository softwareRepo,
            CanonicalCpeLinkingService linker,
            EntityManager em,
            PlatformTransactionManager txManager
    ) {
        this.softwareRepo = softwareRepo;
        this.linker = linker;
        this.em = em;

        TransactionTemplate tt = new TransactionTemplate(txManager);
        tt.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.chunkTx = tt;
    }

    public BackfillResult backfill(int maxRows, boolean forceRebuild) {
        int safeMax = Math.max(1, Math.min(maxRows, 5_000_000));

        int scanned = 0;
        int linked = 0;
        int missed = 0;

        List<SoftwareInstall> all = softwareRepo.findAll();

        for (int offset = 0; offset < all.size() && scanned < safeMax; offset += TX_CHUNK) {
            int to = Math.min(all.size(), offset + TX_CHUNK);
            List<SoftwareInstall> chunk = all.subList(offset, to);

            int remaining = safeMax - scanned;

            int[] result = chunkTx.execute(status -> {
                int processedInChunk = 0;
                int _linked = 0;
                int _missed = 0;

                for (SoftwareInstall s : chunk) {

                    if (processedInChunk >= remaining) break;

                    boolean already = (s.getCpeVendorId() != null || s.getCpeProductId() != null);
                    if (already && !forceRebuild) {
                        processedInChunk++;
                        continue;
                    }

                    var res = linker.resolve(s);
                    if (res.hit()) {
                        s.linkCanonical(res.vendorId(), res.productId());
                        _linked++;
                    } else {
                        _missed++;
                    }

                    processedInChunk++;

                    if (processedInChunk % FLUSH_EVERY == 0) {
                        em.flush();
                        em.clear();
                    }
                }

                em.flush();
                em.clear();
                return new int[]{processedInChunk, _linked, _missed};
            });

            if (result != null) {
                scanned += result[0];
                linked += result[1];
                missed += result[2];
            }

            if (scanned % LOG_EVERY == 0) {
                log.info("Canonical backfill progress: scanned={}, linked={}, missed={}", scanned, linked, missed);
            }
        }

        log.info("Canonical backfill done: scanned={}, linked={}, missed={}", scanned, linked, missed);
        return new BackfillResult(scanned, linked, missed, forceRebuild);
    }
    public record BackfillResult(int scanned, int linked, int missed, boolean forceRebuild) {}
}
