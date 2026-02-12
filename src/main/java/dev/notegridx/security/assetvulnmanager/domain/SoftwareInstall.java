package dev.notegridx.security.assetvulnmanager.domain;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;

import lombok.Getter;

@Entity
@Table(name = "software_installs", indexes = {
		@Index(name = "idx_sw_asset_id", columnList = "asset_id"),
		@Index(name = "idx_sw_cpe", columnList = "cpe_name"),
		@Index(name = "idx_sw_norm", columnList = "normalized_vendor, normalized_product")
})
@Getter
public class SoftwareInstall {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@ManyToOne(fetch = FetchType.LAZY, optional = false)
	@JoinColumn(name = "asset_id", nullable = false)
	private Asset asset;

	private String vendor;

	@NotBlank
	@Column(nullable = false)
	private String product;

	@Column(length = 64)
	private String version;

	@Column(name = "cpe_name", length = 512)
	private String cpeName;

	@Column(name = "normalized_vendor")
	private String normalizedVendor;

	@Column(name = "normalized_product")
	private String normalizedProduct;

	@Column(name = "created_at", nullable = false)
	private LocalDateTime createdAt;

	@Column(name = "updated_at", nullable = false)
	private LocalDateTime updatedAt;

	protected SoftwareInstall() {

	}

	public SoftwareInstall(Asset asset, String product) {
		this.asset = asset;
		this.product = requireNotBlank(product, "product");
	}

	public void updateDetails(String vendor, String product, String version, String cpeName) {
		String p = requireNotBlank(product, "product");
		this.product = p;

		this.vendor = normalizeNullable(vendor);
		this.version = normalizeNullable(version);

		String cpe = normalizeNullable(cpeName);
		this.cpeName = (cpe == null) ? null : cpe;

		this.normalizedVendor = normalizeForKey(this.vendor);
		this.normalizedProduct = normalizeForKey(this.product);
	}

	private static String normalizeNullable(String s) {
		if (s == null) return null;
		String t = s.trim();
		return t.isEmpty() ? null : t;
	}
	
	private static String normalizeForKey(String s) {
		if (s == null) return null;
		String x = s.trim().toLowerCase();
		x = x.replaceAll("\\s+", " ");
		x = x.replaceAll("[\\p{Punct}&&[^._-]]+", "");
		x = x.replaceAll("\\s+", " ").trim();
		return x.isEmpty() ? null : x;
	}

	private static String requireNotBlank(String s, String field) {
		if (s == null || s.trim().isEmpty()) throw new IllegalArgumentException(field + " is required");
		return s.trim();
	}
	
	@PrePersist
	void prePersist() {
		LocalDateTime now = LocalDateTime.now();
		this.createdAt = now;
		this.updatedAt = now;
		if (this.normalizedVendor == null) this.normalizedVendor = normalizeForKey(this.vendor);
		if (this.normalizedProduct == null) this.normalizedProduct = normalizeForKey(this.product);
	}

	@PreUpdate
	void preUpdate() {
		this.updatedAt = LocalDateTime.now();
		if (this.normalizedVendor == null) this.normalizedVendor = normalizeForKey(this.vendor);
		if (this.normalizedProduct == null) this.normalizedProduct = normalizeForKey(this.product);
	}

}
