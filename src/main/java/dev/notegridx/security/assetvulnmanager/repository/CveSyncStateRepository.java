package dev.notegridx.security.assetvulnmanager.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import dev.notegridx.security.assetvulnmanager.domain.CveSyncState;

public interface CveSyncStateRepository extends JpaRepository<CveSyncState, Long> {
    Optional<CveSyncState> findByFeedName(String feedName);
}