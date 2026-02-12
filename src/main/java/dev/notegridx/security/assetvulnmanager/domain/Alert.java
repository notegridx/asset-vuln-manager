package dev.notegridx.security.assetvulnmanager.domain;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
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
import jakarta.persistence.UniqueConstraint;

import dev.notegridx.security.assetvulnmanager.domain.enums.AlertStatus;
import dev.notegridx.security.assetvulnmanager.domain.enums.CloseReason;
import lombok.Getter;

@Entity
@Table(name = "alerts", uniqueConstraints = @UniqueConstraint(name = "uq_alert_pair", columnNames = {
		"software_install_id", "vulnerability_id" }), indexes = {
				@Index(name = "idx_alert_status", columnList = "status"),
				@Index(name = "idx_alert_vuln", columnList = "vulnerability_id"),
				@Index(name = "idx_alert_sw", columnList = "software_install_id")
		})
@Getter
public class Alert {
	
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	
	@ManyToOne(fetch = FetchType.LAZY, optional = false)
	@JoinColumn(name = "software_install_id", nullable = false)
	private SoftwareInstall softwareInstall;
	
	@ManyToOne(fetch = FetchType.LAZY, optional = false)
	@JoinColumn(name = "vulnerability_id", nullable = false)
	private Vulnerability vulnerability;
	
	@Enumerated(EnumType.STRING)
	@Column(nullable = false, length = 16)
	private AlertStatus status = AlertStatus.OPEN;
	
	@Enumerated(EnumType.STRING)
	@Column(name = "close_reason", length = 255)
	private CloseReason closeReason;
	
	@Column(name = "first_seen_at", nullable = false)
	private LocalDateTime firstSeenAt;
	
	@Column(name = "last_seen_at", nullable = false)
	private LocalDateTime lastSeenAt;
	
	@Column(name = "closed_at")
	private LocalDateTime closedAt;
	
	@Column(name = "created_at", nullable = false)
	private LocalDateTime createdAt;
	
	@Column(name = "updated_at", nullable = false)
	private LocalDateTime updatedAt;
	
	protected Alert() {
		
	}
	
	public Alert(SoftwareInstall softwareInstall, Vulnerability vulnerability, LocalDateTime detectedAt) {
		this.softwareInstall = softwareInstall;
		this.vulnerability = vulnerability;
		this.firstSeenAt = detectedAt;
		this.lastSeenAt = detectedAt;
		this.status = AlertStatus.OPEN;
	}
	
	public void touchDetected(LocalDateTime detectedAt) {
		this.lastSeenAt = detectedAt;
	}
	
	public void close(CloseReason reason, LocalDateTime closedAt) {
		this.status = AlertStatus.CLOSED;
		this.closeReason = reason;
		this.closedAt = closedAt;
	}
	
	@PrePersist
	void prePersist() {
		LocalDateTime now = LocalDateTime.now();
		this.createdAt = now;
		this.updatedAt = now;
		if (this.firstSeenAt == null) this.firstSeenAt = now;
		if (this.lastSeenAt == null) this.lastSeenAt = this.firstSeenAt;
		if (this.status == null) this.status = AlertStatus.OPEN;
	}
	
	@PreUpdate
	void preUpdate() {
		this.updatedAt = LocalDateTime.now();
		if (this.status == null) this.status = AlertStatus.OPEN;
	}

}