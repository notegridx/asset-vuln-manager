package dev.notegridx.security.assetvulnmanager.repository;

import java.util.List;
import java.util.Optional;

import dev.notegridx.security.assetvulnmanager.domain.AdminRun;
import dev.notegridx.security.assetvulnmanager.domain.enums.AdminJobType;
import dev.notegridx.security.assetvulnmanager.domain.enums.AdminRunStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AdminRunRepository extends JpaRepository<AdminRun, Long> {

    // Used by /admin/runs to fetch recent runs (fixed upper bound, then trimmed in service if needed)
    List<AdminRun> findTop200ByOrderByStartedAtDescIdDesc();

    // Used by /admin/sync to fetch the latest run for a specific job type
    Optional<AdminRun> findTop1ByJobTypeOrderByStartedAtDescIdDesc(AdminJobType jobType);

    // Used when only job type is specified in the /admin/runs filter
    Page<AdminRun> findByJobTypeOrderByStartedAtDescIdDesc(
            AdminJobType jobType,
            Pageable pageable
    );

    // Used when only status is specified in the /admin/runs filter
    Page<AdminRun> findByStatusOrderByStartedAtDescIdDesc(
            AdminRunStatus status,
            Pageable pageable
    );

    // Used when both job type and status are specified in the /admin/runs filter
    Page<AdminRun> findByJobTypeAndStatusOrderByStartedAtDescIdDesc(
            AdminJobType jobType,
            AdminRunStatus status,
            Pageable pageable
    );

    // Used when no enum filter is specified and the service still needs paged results
    Page<AdminRun> findAllByOrderByStartedAtDescIdDesc(Pageable pageable);
}