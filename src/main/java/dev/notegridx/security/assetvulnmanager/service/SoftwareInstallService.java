package dev.notegridx.security.assetvulnmanager.service;

import java.util.List;

import jakarta.persistence.EntityNotFoundException;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;

@Service
public class SoftwareInstallService {
	
	private final SoftwareInstallRepository softwareInstallRepository;
	
	public SoftwareInstallService(SoftwareInstallRepository softwareInstallRepository) {
		this.softwareInstallRepository = softwareInstallRepository;
	}
	
	@Transactional(readOnly = true)
	public List<SoftwareInstall> findByAssetId(Long assetId) {
		return softwareInstallRepository.findByAssetIdOrderByIdDesc(assetId);
	}
	
	@Transactional(readOnly = true)
	public SoftwareInstall getRequired(Long id) {
		return softwareInstallRepository.findById(id)
				.orElseThrow(() -> new EntityNotFoundException("SoftwareInstall not found. id=" + id));
	}
	
	@Transactional
	public SoftwareInstall addToAsset(Asset asset, String vendor, String product, String version, String cpeName) {
		SoftwareInstall si = new SoftwareInstall(asset, product);
		si.updateDetails(vendor, product, version, cpeName);
		return softwareInstallRepository.save(si);
	}
	
	@Transactional
	public SoftwareInstall updateDetails(Long softwareInstallId, String vendor, String product, String version, String cpeName) {
		SoftwareInstall si = getRequired(softwareInstallId);
		si.updateDetails(vendor, product, version, cpeName);
		return softwareInstallRepository.save(si);
	}
	

}
