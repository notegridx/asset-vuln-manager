package dev.notegridx.security.assetvulnmanager.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import dev.notegridx.security.assetvulnmanager.domain.KevSyncState;

public interface KevSyncStateRepository extends JpaRepository<KevSyncState, Long> {
    Optional<KevSyncState> findByFeedName(String feedName);
}