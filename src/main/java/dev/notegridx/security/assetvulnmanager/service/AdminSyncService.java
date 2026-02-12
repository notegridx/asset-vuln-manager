package dev.notegridx.security.assetvulnmanager.service;


import java.time.OffsetDateTime;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AdminSyncService {
	
	private static final Logger log = LoggerFactory.getLogger(AdminSyncService.class);
	
	private final NvdImportService nvdImportService;
	private final MatchingService matchingService;
	

	
	public AdminSyncService(NvdImportService nvdImportService,
			MatchingService matchingService) {
		this.nvdImportService = nvdImportService;
		this.matchingService = matchingService;
	}
	
	@Transactional
	public SyncResult runSync(int daysBack, int maxResults) {
		int safeDays = Math.max(1, Math.min(daysBack, 120));
		int safeMax = Math.max(1, Math.min(maxResults, 2000));
		
		OffsetDateTime end = OffsetDateTime.now();
		OffsetDateTime start = end.minusDays(safeDays);
		
		var importResult = nvdImportService.importFromNvd(start, end, safeMax);
		var matchResult = matchingService.matchAndUpsertAlerts();
		
		log.info("Sync done: fetched={}, vulnUpserted={}, affectedInserted={}, pairsFound={}, alertsInserted={}, alertsTouched={}", importResult.fetched(), importResult.vulnerabilitiesUpserted(), importResult.affectedCpesInserted(), matchResult.pairsFound(), matchResult.alertsInserted(), matchResult.alertsTouched());
		
		return new SyncResult(
				importResult.vulnerabilitiesUpserted(),
				importResult.affectedCpesInserted(),
				importResult.fetched(),
				matchResult.pairsFound(),
				matchResult.alertsInserted(),
				matchResult.alertsTouched());
	}
	
	public record SyncResult(
			int vulnerabilitiesUpserted,
			int affectedCpesInserted,
			int fetched,
			int pairsFound,
			int alertsInserted,
			int alertsTouched) {
		
	}


}
