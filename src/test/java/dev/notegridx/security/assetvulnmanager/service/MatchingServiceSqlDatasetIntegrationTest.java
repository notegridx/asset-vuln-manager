package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.Alert;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertCertainty;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertMatchMethod;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertStatus;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertUncertainReason;
import dev.notegridx.security.assetvulnmanager.domain.enums.CloseReason;
import dev.notegridx.security.assetvulnmanager.repository.AlertRepository;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import dev.notegridx.security.assetvulnmanager.repository.VulnerabilityRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.jdbc.Sql;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ActiveProfiles("mysqltest")
@Testcontainers
class MatchingServiceSqlDatasetIntegrationTest {

    @Autowired
    private MatchingService matchingService;

    @Autowired
    private AlertRepository alertRepository;

    @Autowired
    private SoftwareInstallRepository softwareInstallRepository;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    private Alert findAlert(long softwareInstallId, long vulnerabilityId) {
        return alertRepository
                .findBySoftwareInstallIdAndVulnerabilityId(softwareInstallId, vulnerabilityId)
                .orElse(null);
    }

    private void assertSeedPresent(long softwareInstallId, long vulnerabilityId) {
        assertThat(softwareInstallRepository.findById(softwareInstallId)).isPresent();
        assertThat(vulnerabilityRepository.findById(vulnerabilityId)).isPresent();
    }

    @Test
    @Sql(scripts = {
            "/sql/matching/cleanup.sql",
            "/sql/matching/common-master.sql",
            "/sql/matching/case01_dict_id_no_version_constraint.sql"
    })
    void case01_dictId_noVersionConstraint_generatesUnconfirmedAlert() {
        assertSeedPresent(3001L, 2001L);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result).isNotNull();
        assertThat(result.pairsFound()).isEqualTo(1);
        assertThat(result.alertsInserted()).isEqualTo(1);
        assertThat(result.alertsTouched()).isZero();
        assertThat(result.alertsAutoClosed()).isZero();

        Alert alert = findAlert(3001L, 2001L);
        assertThat(alert).isNotNull();
        assertThat(alert.getStatus()).isEqualTo(AlertStatus.OPEN);
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.UNCONFIRMED);
        assertThat(alert.getUncertainReason()).isEqualTo(AlertUncertainReason.NO_VERSION_CONSTRAINT);
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.DICT_ID);
        assertThat(alert.getCloseReason()).isNull();
        assertThat(alert.getClosedAt()).isNull();
        assertThat(alertRepository.findAll()).hasSize(1);
    }

    @Test
    @Sql(scripts = {
            "/sql/matching/cleanup.sql",
            "/sql/matching/common-master.sql",
            "/sql/matching/case02_dict_id_inclusive_match.sql"
    })
    void case02_dictId_inclusiveRange_generatesConfirmedAlert() {
        assertSeedPresent(3002L, 2002L);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result).isNotNull();
        assertThat(result.pairsFound()).isEqualTo(1);
        assertThat(result.alertsInserted()).isEqualTo(1);
        assertThat(result.alertsTouched()).isZero();
        assertThat(result.alertsAutoClosed()).isZero();

        Alert alert = findAlert(3002L, 2002L);
        assertThat(alert).isNotNull();
        assertThat(alert.getStatus()).isEqualTo(AlertStatus.OPEN);
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.CONFIRMED);
        assertThat(alert.getUncertainReason()).isNull();
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.DICT_ID);
        assertThat(alertRepository.findAll()).hasSize(1);
    }

    @Test
    @Sql(scripts = {
            "/sql/matching/cleanup.sql",
            "/sql/matching/common-master.sql",
            "/sql/matching/case03_dict_id_lower_inclusive_boundary.sql"
    })
    void case03_lowerInclusiveBoundary_generatesConfirmedAlert() {
        assertSeedPresent(3003L, 2003L);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result).isNotNull();
        assertThat(result.pairsFound()).isEqualTo(1);
        assertThat(result.alertsInserted()).isEqualTo(1);
        assertThat(result.alertsTouched()).isZero();
        assertThat(result.alertsAutoClosed()).isZero();

        Alert alert = findAlert(3003L, 2003L);
        assertThat(alert).isNotNull();
        assertThat(alert.getStatus()).isEqualTo(AlertStatus.OPEN);
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.CONFIRMED);
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.DICT_ID);
        assertThat(alert.getUncertainReason()).isNull();
        assertThat(alertRepository.findAll()).hasSize(1);
    }

    @Test
    @Sql(scripts = {
            "/sql/matching/cleanup.sql",
            "/sql/matching/common-master.sql",
            "/sql/matching/case04_dict_id_lower_exclusive_boundary.sql"
    })
    void case04_lowerExclusiveBoundary_doesNotGenerateAlert() {
        assertSeedPresent(3004L, 2004L);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result).isNotNull();
        assertThat(result.pairsFound()).isZero();
        assertThat(result.alertsInserted()).isZero();
        assertThat(result.alertsTouched()).isZero();
        assertThat(result.alertsAutoClosed()).isZero();

        Alert alert = findAlert(3004L, 2004L);
        assertThat(alert).isNull();
        assertThat(alertRepository.findAll()).isEmpty();
    }

    @Test
    @Sql(scripts = {
            "/sql/matching/cleanup.sql",
            "/sql/matching/common-master.sql",
            "/sql/matching/case05_dict_id_upper_inclusive_boundary.sql"
    })
    void case05_upperInclusiveBoundary_generatesConfirmedAlert() {
        assertSeedPresent(3005L, 2005L);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result).isNotNull();
        assertThat(result.pairsFound()).isEqualTo(1);
        assertThat(result.alertsInserted()).isEqualTo(1);
        assertThat(result.alertsTouched()).isZero();
        assertThat(result.alertsAutoClosed()).isZero();

        Alert alert = findAlert(3005L, 2005L);
        assertThat(alert).isNotNull();
        assertThat(alert.getStatus()).isEqualTo(AlertStatus.OPEN);
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.CONFIRMED);
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.DICT_ID);
        assertThat(alertRepository.findAll()).hasSize(1);
    }

    @Test
    @Sql(scripts = {
            "/sql/matching/cleanup.sql",
            "/sql/matching/common-master.sql",
            "/sql/matching/case06_dict_id_upper_exclusive_boundary.sql"
    })
    void case06_upperExclusiveBoundary_doesNotGenerateAlert() {
        assertSeedPresent(3006L, 2006L);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result).isNotNull();
        assertThat(result.pairsFound()).isZero();
        assertThat(result.alertsInserted()).isZero();
        assertThat(result.alertsTouched()).isZero();
        assertThat(result.alertsAutoClosed()).isZero();

        Alert alert = findAlert(3006L, 2006L);
        assertThat(alert).isNull();
        assertThat(alertRepository.findAll()).isEmpty();
    }

    @Test
    @Sql(scripts = {
            "/sql/matching/cleanup.sql",
            "/sql/matching/common-master.sql",
            "/sql/matching/case07_dict_id_missing_software_version.sql"
    })
    void case07_missingSoftwareVersion_generatesUnconfirmedAlert() {
        assertSeedPresent(3007L, 2007L);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result).isNotNull();
        assertThat(result.pairsFound()).isEqualTo(1);
        assertThat(result.alertsInserted()).isEqualTo(1);
        assertThat(result.alertsTouched()).isZero();
        assertThat(result.alertsAutoClosed()).isZero();

        Alert alert = findAlert(3007L, 2007L);
        assertThat(alert).isNotNull();
        assertThat(alert.getStatus()).isEqualTo(AlertStatus.OPEN);
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.UNCONFIRMED);
        assertThat(alert.getUncertainReason()).isEqualTo(AlertUncertainReason.MISSING_SOFTWARE_VERSION);
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.DICT_ID);
        assertThat(alertRepository.findAll()).hasSize(1);
    }

    @Test
    @Sql(scripts = {
            "/sql/matching/cleanup.sql",
            "/sql/matching/common-master.sql",
            "/sql/matching/case08_dict_id_non_numeric_version_no_alert.sql"
    })
    void case08_nonNumericSoftwareVersion_doesNotGenerateAlert() {
        assertSeedPresent(3008L, 2008L);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result).isNotNull();
        assertThat(result.pairsFound()).isZero();
        assertThat(result.alertsInserted()).isZero();
        assertThat(result.alertsTouched()).isZero();
        assertThat(result.alertsAutoClosed()).isZero();

        Alert alert = findAlert(3008L, 2008L);
        assertThat(alert).isNull();
        assertThat(alertRepository.findAll()).isEmpty();
    }

    @Test
    @Sql(scripts = {
            "/sql/matching/cleanup.sql",
            "/sql/matching/common-master.sql",
            "/sql/matching/case09_norm_fallback_match.sql"
    })
    void case09_normFallback_generatesConfirmedAlert() {
        assertSeedPresent(3009L, 2009L);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result).isNotNull();
        assertThat(result.pairsFound()).isEqualTo(1);
        assertThat(result.alertsInserted()).isEqualTo(1);
        assertThat(result.alertsTouched()).isZero();
        assertThat(result.alertsAutoClosed()).isZero();

        Alert alert = findAlert(3009L, 2009L);
        assertThat(alert).isNotNull();
        assertThat(alert.getStatus()).isEqualTo(AlertStatus.OPEN);
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.CONFIRMED);
        assertThat(alert.getUncertainReason()).isNull();
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.NORM);
        assertThat(alertRepository.findAll()).hasSize(1);
    }

    @Test
    @Sql(scripts = {
            "/sql/matching/cleanup.sql",
            "/sql/matching/common-master.sql",
            "/sql/matching/case10_norm_fallback_no_match.sql"
    })
    void case10_normFallback_outOfRange_doesNotGenerateAlert() {
        assertSeedPresent(3010L, 2010L);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result).isNotNull();
        assertThat(result.pairsFound()).isZero();
        assertThat(result.alertsInserted()).isZero();
        assertThat(result.alertsTouched()).isZero();
        assertThat(result.alertsAutoClosed()).isZero();

        Alert alert = findAlert(3010L, 2010L);
        assertThat(alert).isNull();
        assertThat(alertRepository.findAll()).isEmpty();
    }

    @Test
    @Sql(scripts = {
            "/sql/matching/cleanup.sql",
            "/sql/matching/common-master.sql",
            "/sql/matching/case11_cpe_name_match.sql"
    })
    void case11_cpeNameFallback_generatesConfirmedAlert() {
        assertSeedPresent(3011L, 2011L);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result).isNotNull();
        assertThat(result.pairsFound()).isEqualTo(1);
        assertThat(result.alertsInserted()).isEqualTo(1);
        assertThat(result.alertsTouched()).isZero();
        assertThat(result.alertsAutoClosed()).isZero();

        Alert alert = findAlert(3011L, 2011L);
        assertThat(alert).isNotNull();
        assertThat(alert.getStatus()).isEqualTo(AlertStatus.OPEN);
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.CONFIRMED);
        assertThat(alert.getUncertainReason()).isNull();
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.CPE_NAME);
        assertThat(alertRepository.findAll()).hasSize(1);
    }

    @Test
    @Sql(scripts = {
            "/sql/matching/cleanup.sql",
            "/sql/matching/common-master.sql",
            "/sql/matching/case12_cpe_name_no_match.sql"
    })
    void case12_cpeNameFallback_outOfRange_doesNotGenerateAlert() {
        assertSeedPresent(3012L, 2012L);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result).isNotNull();
        assertThat(result.pairsFound()).isZero();
        assertThat(result.alertsInserted()).isZero();
        assertThat(result.alertsTouched()).isZero();
        assertThat(result.alertsAutoClosed()).isZero();

        Alert alert = findAlert(3012L, 2012L);
        assertThat(alert).isNull();
        assertThat(alertRepository.findAll()).isEmpty();
    }

    @Test
    @Sql(scripts = {
            "/sql/matching/cleanup.sql",
            "/sql/matching/common-master.sql",
            "/sql/matching/case13_reopen_closed_auto_closed.sql"
    })
    void case13_reopensPreviouslyAutoClosedAlert() {
        assertSeedPresent(3013L, 2013L);
        assertThat(alertRepository.findAll()).hasSize(1);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result).isNotNull();
        assertThat(result.pairsFound()).isEqualTo(1);
        assertThat(result.alertsInserted()).isZero();
        assertThat(result.alertsTouched()).isEqualTo(1);
        assertThat(result.alertsAutoClosed()).isZero();

        Alert alert = findAlert(3013L, 2013L);
        assertThat(alert).isNotNull();
        assertThat(alert.getId()).isEqualTo(5001L);
        assertThat(alert.getStatus()).isEqualTo(AlertStatus.OPEN);
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.CONFIRMED);
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.DICT_ID);
        assertThat(alert.getCloseReason()).isNull();
        assertThat(alert.getClosedAt()).isNull();
        assertThat(alertRepository.findAll()).hasSize(1);
    }

    @Test
    @Sql(scripts = {
            "/sql/matching/cleanup.sql",
            "/sql/matching/common-master.sql",
            "/sql/matching/case14_touch_existing_open.sql"
    })
    void case14_touchesExistingOpenAlert() {
        assertSeedPresent(3014L, 2014L);
        assertThat(alertRepository.findAll()).hasSize(1);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result).isNotNull();
        assertThat(result.pairsFound()).isEqualTo(1);
        assertThat(result.alertsInserted()).isZero();
        assertThat(result.alertsTouched()).isEqualTo(1);
        assertThat(result.alertsAutoClosed()).isZero();

        Alert alert = findAlert(3014L, 2014L);
        assertThat(alert).isNotNull();
        assertThat(alert.getId()).isEqualTo(5002L);
        assertThat(alert.getStatus()).isEqualTo(AlertStatus.OPEN);
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.CONFIRMED);
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.DICT_ID);
        assertThat(alert.getCloseReason()).isNull();
        assertThat(alert.getClosedAt()).isNull();
        assertThat(alertRepository.findAll()).hasSize(1);
    }

    @Test
    @Sql(scripts = {
            "/sql/matching/cleanup.sql",
            "/sql/matching/common-master.sql",
            "/sql/matching/case15_auto_close_stale_open.sql"
    })
    void case15_autoClosesStaleOpenAlert() {
        assertSeedPresent(3015L, 2015L);
        assertThat(alertRepository.findAll()).hasSize(1);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result).isNotNull();
        assertThat(result.pairsFound()).isZero();
        assertThat(result.alertsInserted()).isZero();
        assertThat(result.alertsTouched()).isZero();
        assertThat(result.alertsAutoClosed()).isEqualTo(1);

        Alert alert = findAlert(3015L, 2015L);
        assertThat(alert).isNotNull();
        assertThat(alert.getId()).isEqualTo(5003L);
        assertThat(alert.getStatus()).isEqualTo(AlertStatus.CLOSED);
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.CONFIRMED);
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.DICT_ID);
        assertThat(alert.getCloseReason()).isEqualTo(CloseReason.AUTO_CLOSED_NO_LONGER_AFFECTED);
        assertThat(alert.getClosedAt()).isNotNull();
        assertThat(alertRepository.findAll()).hasSize(1);
    }

    @Test
    @Sql(scripts = {
            "/sql/matching/cleanup.sql",
            "/sql/matching/common-master.sql",
            "/sql/matching/case16_best_verdict_match_wins.sql"
    })
    void case16_bestVerdict_matchBeatsNoMatch() {
        assertSeedPresent(3016L, 2016L);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result).isNotNull();
        assertThat(result.pairsFound()).isEqualTo(1);
        assertThat(result.alertsInserted()).isEqualTo(1);
        assertThat(result.alertsTouched()).isZero();
        assertThat(result.alertsAutoClosed()).isZero();

        Alert alert = findAlert(3016L, 2016L);
        assertThat(alert).isNotNull();
        assertThat(alert.getStatus()).isEqualTo(AlertStatus.OPEN);
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.CONFIRMED);
        assertThat(alert.getUncertainReason()).isNull();
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.DICT_ID);
        assertThat(alertRepository.findAll()).hasSize(1);
    }

    @Test
    @Sql(scripts = {
            "/sql/matching/cleanup.sql",
            "/sql/matching/common-master.sql",
            "/sql/matching/case17_best_verdict_unknown_wins.sql"
    })
    void case17_bestVerdict_unknownBeatsNoMatch() {
        assertSeedPresent(3017L, 2017L);

        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result).isNotNull();
        assertThat(result.pairsFound()).isEqualTo(1);
        assertThat(result.alertsInserted()).isEqualTo(1);
        assertThat(result.alertsTouched()).isZero();
        assertThat(result.alertsAutoClosed()).isZero();

        Alert alert = findAlert(3017L, 2017L);
        assertThat(alert).isNotNull();
        assertThat(alert.getStatus()).isEqualTo(AlertStatus.OPEN);
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.UNCONFIRMED);
        assertThat(alert.getUncertainReason()).isEqualTo(AlertUncertainReason.MISSING_SOFTWARE_VERSION);
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.DICT_ID);
        assertThat(alert.getCloseReason()).isNull();
        assertThat(alert.getClosedAt()).isNull();
        assertThat(alertRepository.findAll()).hasSize(1);
    }

    @Test
    @Sql(scripts = {
            "/sql/matching/cleanup.sql",
            "/sql/matching/common-master.sql",
            "/sql/matching/case18_dict_id_windows_target_sw_match.sql"
    })
    void case18_windowsTargetSw_match_generatesConfirmedAlert() {
        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result).isNotNull();
        assertThat(result.pairsFound()).isEqualTo(1);
        assertThat(result.alertsInserted()).isEqualTo(1);
        assertThat(result.alertsTouched()).isZero();
        assertThat(result.alertsAutoClosed()).isZero();

        Alert alert = findAlert(3018L, 2018L);
        assertThat(alert).isNotNull();
        assertThat(alert.getStatus()).isEqualTo(AlertStatus.OPEN);
        assertThat(alert.getCertainty()).isEqualTo(AlertCertainty.CONFIRMED);
        assertThat(alert.getMatchedBy()).isEqualTo(AlertMatchMethod.DICT_ID);
    }

    @Test
    @Sql(scripts = {
            "/sql/matching/cleanup.sql",
            "/sql/matching/common-master.sql",
            "/sql/matching/case19_dict_id_mac_target_sw_no_match_on_windows.sql"
    })
    void case19_macTargetSw_onWindows_doesNotGenerateAlert() {
        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result).isNotNull();
        assertThat(result.pairsFound()).isZero();
        assertThat(result.alertsInserted()).isZero();
        assertThat(result.alertsTouched()).isZero();
        assertThat(result.alertsAutoClosed()).isZero();

        Alert alert = findAlert(3019L, 2019L);
        assertThat(alert).isNull();
    }

    @Test
    @Sql(scripts = {
            "/sql/matching/cleanup.sql",
            "/sql/matching/common-master.sql",
            "/sql/matching/case20_dict_id_iphone_os_no_match.sql"
    })
    void case20_iphoneOs_doesNotGenerateAlert() {
        var result = matchingService.matchAndUpsertAlerts();

        assertThat(result).isNotNull();
        assertThat(result.pairsFound()).isZero();
        assertThat(result.alertsInserted()).isZero();
        assertThat(result.alertsTouched()).isZero();
        assertThat(result.alertsAutoClosed()).isZero();

        Alert alert = findAlert(3020L, 2020L);
        assertThat(alert).isNull();
    }
}