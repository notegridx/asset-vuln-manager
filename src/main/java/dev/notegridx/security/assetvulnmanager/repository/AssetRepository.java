package dev.notegridx.security.assetvulnmanager.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import dev.notegridx.security.assetvulnmanager.domain.Asset;

public interface AssetRepository extends JpaRepository<Asset, Long> {
	List<Asset> findByNameContainingIgnoreCaseOrderByIdDesc(String name);

	Optional<Asset> findByExternalKey(String externalKey);

	boolean existsByExternalKey(String externalKey);
}
