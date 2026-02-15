package dev.notegridx.security.assetvulnmanager.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;

public interface SoftwareInstallRepository extends JpaRepository<SoftwareInstall, Long> {

	List<SoftwareInstall> findByCpeNameIsNotNull();
	
	List<SoftwareInstall> findByAssetIdOrderByIdDesc(Long assetId);
	
	List<SoftwareInstall> findByNormalizedVendorAndNormalizedProduct(String normalizedVendor, String normalizedProduct);

	Optional<SoftwareInstall> findByAssetIdAndVendorAndProductAndVersion(
			Long assetId, String vendor, String product, String version);

	boolean existsByAssetIdAndVendorAndProductAndVersion(
			Long assetId, String vendor, String product, String version);
}
