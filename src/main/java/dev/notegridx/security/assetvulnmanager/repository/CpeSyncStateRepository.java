package dev.notegridx.security.assetvulnmanager.repository;

import dev.notegridx.security.assetvulnmanager.domain.CpeSyncState;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CpeSyncStateRepository extends JpaRepository<CpeSyncState, Long> {

    Optional<CpeSyncState> findByFeedName(String feedName);
}
