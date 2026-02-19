package dev.notegridx.security.assetvulnmanager.service;

import dev.notegridx.security.assetvulnmanager.domain.Asset;
import dev.notegridx.security.assetvulnmanager.domain.SoftwareInstall;
import dev.notegridx.security.assetvulnmanager.repository.SoftwareInstallRepository;
import jakarta.persistence.EntityNotFoundException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Locale;

@Service
public class SoftwareInstallService {

	public enum DictMode { STRICT, LENIENT }

	private final SoftwareInstallRepository softwareInstallRepository;
	private final SoftwareDictionaryValidator dictValidator;
	private final DictMode dictMode;

	public SoftwareInstallService(
			SoftwareInstallRepository softwareInstallRepository,
			SoftwareDictionaryValidator dictValidator,
			@Value("${app.software.dict-mode:LENIENT}") String dictMode
	) {
		this.softwareInstallRepository = softwareInstallRepository;
		this.dictValidator = dictValidator;
		this.dictMode = parseDictMode(dictMode);
	}

	private static DictMode parseDictMode(String s) {
		if (s == null) return DictMode.LENIENT;
		try {
			return DictMode.valueOf(s.trim().toUpperCase(Locale.ROOT));
		} catch (Exception e) {
			return DictMode.LENIENT;
		}
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
	public SoftwareInstall addToAsset(
			Asset asset,
			String vendor,
			String product,
			String version,
			String cpeName
	) {
		SoftwareDictionaryValidator.Resolve r;
		if (dictMode == DictMode.STRICT) {
			r = dictValidator.resolveOrThrow(vendor, product);
		} else {
			r = dictValidator.resolve(vendor, product);
		}

		SoftwareInstall si = new SoftwareInstall(asset, product);
		si.updateDetails(vendor, product, version, cpeName);

		if (r.hit()) {
			si.linkCanonical(r.vendorId(), r.productId());
		} else {
			// LENIENT時：辞書HITしないなら canonicalリンクは付けない（既存があっても新規はなし）
			si.unlinkCanonical();
		}

		return softwareInstallRepository.save(si);
	}

	@Transactional
	public SoftwareInstall updateDetails(
			Long softwareInstallId,
			String vendor,
			String product,
			String version,
			String cpeName
	) {
		SoftwareDictionaryValidator.Resolve r;
		if (dictMode == DictMode.STRICT) {
			r = dictValidator.resolveOrThrow(vendor, product);
		} else {
			r = dictValidator.resolve(vendor, product);
		}

		SoftwareInstall si = getRequired(softwareInstallId);
		si.updateDetails(vendor, product, version, cpeName);

		if (r.hit()) {
			si.linkCanonical(r.vendorId(), r.productId());
		} else {
			// LENIENT時：入力が変わって辞書に当たらない場合は canonical を外す（古いリンクが残るのを防ぐ）
			si.unlinkCanonical();
		}

		return softwareInstallRepository.save(si);
	}
}
