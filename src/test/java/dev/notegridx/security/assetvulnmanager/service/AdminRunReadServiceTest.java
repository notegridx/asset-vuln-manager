package dev.notegridx.security.assetvulnmanager.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.notegridx.security.assetvulnmanager.domain.AdminRun;
import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import dev.notegridx.security.assetvulnmanager.repository.AdminRunRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class AdminRunReadServiceTest {

    private AdminRunRepository adminRunRepository;
    private AdminRunReadService service;

    @BeforeEach
    void setup() {
        adminRunRepository = mock(AdminRunRepository.class);
        service = new AdminRunReadService(adminRunRepository, new ObjectMapper());
    }

    @Test
    void findLastRun_returnsNull_whenNoRunExists() {
        when(adminRunRepository.findTop1ByJobTypeOrderByStartedAtDescIdDesc(AdminJobType.KEV_SYNC))
                .thenReturn(Optional.empty());

        AdminRunReadService.LastRunView result =
                service.findLastRun(
                        AdminJobType.KEV_SYNC,
                        AdminRunReadService.ParseErrorStyle.MESSAGE_AND_RAW
                );

        assertThat(result).isNull();
    }

    @Test
    void findLastRun_parsesObjectJson_forSimpleClassNameStyle() {
        AdminRun run = adminRun(
                "{\"daysBack\":1,\"maxResults\":200}",
                "{\"processed\":10}"
        );

        when(adminRunRepository.findTop1ByJobTypeOrderByStartedAtDescIdDesc(AdminJobType.CVE_DELTA_UPDATE))
                .thenReturn(Optional.of(run));

        AdminRunReadService.LastRunView result =
                service.findLastRun(
                        AdminJobType.CVE_DELTA_UPDATE,
                        AdminRunReadService.ParseErrorStyle.SIMPLE_CLASS_NAME
                );

        assertThat(result).isNotNull();
        assertThat(result.run()).isSameAs(run);
        assertThat(result.params()).containsEntry("daysBack", 1);
        assertThat(result.params()).containsEntry("maxResults", 200);
        assertThat(result.result()).containsEntry("processed", 10);
    }

    @Test
    void findLastRun_returnsParseErrorAndRaw_forMessageAndRawStyle() {
        AdminRun run = adminRun(
                "{bad-json",
                "[1,2,3]"
        );

        when(adminRunRepository.findTop1ByJobTypeOrderByStartedAtDescIdDesc(AdminJobType.KEV_SYNC))
                .thenReturn(Optional.of(run));

        AdminRunReadService.LastRunView result =
                service.findLastRun(
                        AdminJobType.KEV_SYNC,
                        AdminRunReadService.ParseErrorStyle.MESSAGE_AND_RAW
                );

        assertThat(result).isNotNull();

        assertThat(result.params()).containsEntry("_raw", "{bad-json");
        assertThat(result.params()).containsKey("_parseError");

        assertThat(result.result()).containsEntry("_raw", "[1,2,3]");
        assertThat(result.result()).containsKey("_parseError");
    }

    @Test
    void findRecentRuns_convertsObjectJsonToFriendlyMap() {
        AdminRun run = adminRun(
                "{\"mode\":\"FULL\",\"processed\":10,\"dryRun\":false,\"empty\":null}",
                "{\"status\":\"ok\"}"
        );

        when(adminRunRepository.findTop200ByOrderByStartedAtDescIdDesc())
                .thenReturn(List.of(run));

        List<AdminRunReadService.AdminRunRow> rows = service.findRecentRuns(200);

        assertThat(rows).hasSize(1);

        AdminRunReadService.AdminRunRow row = rows.get(0);
        assertThat(row.run()).isSameAs(run);
        assertThat(row.params()).containsEntry("mode", "FULL");
        assertThat(row.params()).containsEntry("processed", "10");
        assertThat(row.params()).containsEntry("dryRun", "false");
        assertThat(row.params()).containsEntry("empty", "null");
        assertThat(row.result()).containsEntry("status", "ok");
    }

    @Test
    void findRecentRuns_keepsNonObjectJsonAsRaw() {
        AdminRun run = adminRun(
                "[1,2,3]",
                "\"OK\""
        );

        when(adminRunRepository.findTop200ByOrderByStartedAtDescIdDesc())
                .thenReturn(List.of(run));

        List<AdminRunReadService.AdminRunRow> rows = service.findRecentRuns(200);

        assertThat(rows).hasSize(1);
        assertThat(rows.get(0).params()).isEqualTo(Map.of("_raw", "[1,2,3]"));
        assertThat(rows.get(0).result()).isEqualTo(Map.of("_raw", "\"OK\""));
    }

    @Test
    void findRecentRuns_returnsRawAndParseError_onInvalidJson() {
        AdminRun run = adminRun(
                "{bad-json",
                "{also-bad"
        );

        when(adminRunRepository.findTop200ByOrderByStartedAtDescIdDesc())
                .thenReturn(List.of(run));

        List<AdminRunReadService.AdminRunRow> rows = service.findRecentRuns(200);

        assertThat(rows).hasSize(1);

        Map<String, Object> params = rows.get(0).params();
        Map<String, Object> result = rows.get(0).result();

        assertThat(params).containsEntry("_raw", "{bad-json");
        assertThat(params).containsKey("_parseError");

        assertThat(result).containsEntry("_raw", "{also-bad");
        assertThat(result).containsKey("_parseError");
    }

    @Test
    void findRecentRuns_rendersNestedObjectAndArrayAsCompactJsonStrings() {
        AdminRun run = adminRun(
                "{\"obj\":{\"a\":1,\"b\":true},\"arr\":[1,\"x\",false]}",
                null
        );

        when(adminRunRepository.findTop200ByOrderByStartedAtDescIdDesc())
                .thenReturn(List.of(run));

        List<AdminRunReadService.AdminRunRow> rows = service.findRecentRuns(200);

        assertThat(rows).hasSize(1);
        assertThat(rows.get(0).params()).containsEntry("obj", "{\"a\":1,\"b\":true}");
        assertThat(rows.get(0).params()).containsEntry("arr", "[1,\"x\",false]");
        assertThat(rows.get(0).result()).isNull();
    }

    @Test
    void findRecentRuns_returnsNullForEmptyObjectJson() {
        AdminRun run = adminRun(
                "{}",
                "{}"
        );

        when(adminRunRepository.findTop200ByOrderByStartedAtDescIdDesc())
                .thenReturn(List.of(run));

        List<AdminRunReadService.AdminRunRow> rows = service.findRecentRuns(200);

        assertThat(rows).hasSize(1);
        assertThat(rows.get(0).params()).isNull();
        assertThat(rows.get(0).result()).isNull();
    }

    private AdminRun adminRun(String paramsJson, String resultJson) {
        AdminRun run = AdminRun.start(AdminJobType.KEV_SYNC, paramsJson);
        run.setParamsJson(paramsJson);
        run.setResultJson(resultJson);
        return run;
    }
}