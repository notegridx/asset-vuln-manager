package dev.notegridx.security.assetvulnmanager.domain;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.OneToMany;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;

import lombok.Getter;

@Entity
@Table(name = "assets")
@Getter
public class Asset {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@NotBlank
	@Column(nullable = false)
	private String name;

	@Column(name = "asset_type")
	private String assetType;

	private String owner;

	@Lob
	private String note;

	@Column(name = "created_at", nullable = false)
	private LocalDateTime createdAt;

	@Column(name = "updated_at", nullable = false)
	private LocalDateTime updatedAt;

	@OneToMany(mappedBy = "asset", fetch = FetchType.LAZY, cascade = CascadeType.ALL, orphanRemoval = true)
	private List<SoftwareInstall> softwareInstalls = new ArrayList<>();
	
	protected Asset() {
	}
	
	public Asset(String name) {
		this.name = name;
	}
	
	public void updateDetails(String assetType, String owner, String note) {
		this.assetType = assetType;
		this.owner = owner;
		this.note = note;
	}
	
	@PrePersist
	void prePersist() {
		LocalDateTime now = LocalDateTime.now();
		this.createdAt = now;
		this.updatedAt = now;
	}
	
	@PreUpdate
	void preUpdate() {
		this.updatedAt = LocalDateTime.now();
	}



}
