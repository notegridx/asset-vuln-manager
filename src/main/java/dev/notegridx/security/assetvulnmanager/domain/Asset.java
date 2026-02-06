package dev.notegridx.security.assetvulnmanager.domain;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;

import lombok.Getter;

@Entity
@Table(name = "assets")
@Getter
public class Asset {
	
	@Id @GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	
	@Column(nullable = false) private String name;
	private String vendor;
	
	@Column(nullable = false) private String version;
	
	@Column(name = "asset_type")
	private String assetType;
	private String owner;
	
	@Column(name = "created_at", nullable = false) private LocalDateTime createdAt = LocalDateTime.now();
	@Column(name = "updated_at", nullable = false) private LocalDateTime updatedAt = LocalDateTime.now();
	
	@PrePersist
	void onCreate() {
		createdAt = LocalDateTime.now();
		updatedAt = LocalDateTime.now();
	}
	
	@PreUpdate
	void onUpdate() {
		updatedAt = LocalDateTime.now();
	}
	
	protected Asset() {}
	
	public Asset(String name, String vendor, String version, String assetType, String owner) {
		this.name = name;
		this.vendor = vendor;
		this.version = version;
		this.assetType = assetType;
		this.owner = owner;
	}
	
	public void touchUpdatedAt() {
		this.updatedAt = LocalDateTime.now();
	}
	
}
