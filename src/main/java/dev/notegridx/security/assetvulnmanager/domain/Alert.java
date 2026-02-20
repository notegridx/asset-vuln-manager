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

import dev.notegridx.security.assetvulnmanager.domain.enums.AlertCertainty;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertMatchMethod;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertStatus;
import dev.notegridx.security.assetvulnmanager.domain.enums.AlertUncertainReason;
import dev.notegridx.security.assetvulnmanager.domain.enums.CloseReason;
import lombok.Getter;

@Entity
@Table(
		name = "alerts",
		uniqueConstraints = @UniqueConstraint(
				name = "uq_alert_pair",
				columnNames = {"software_install_id", "vulnerability_id"}
		),
		indexes = {
				@Index(name = "idx_alert_status", columnList = "status"),
				@Index(name = "idx_alert_certainty", columnList = "certainty"),
				@Index(name = "idx_alert_vuln", columnList = "vulnerability_id"),
				@Index(name = "idx_alert_sw", columnList = "software_install_id"),
				@Index(name = "idx_alert_status_certainty", columnList = "status, certainty")
		}
)
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
	@Column(nullable = false, length = 16)
	private AlertCertainty certainty = AlertCertainty.CONFIRMED;

	@Enumerated(EnumType.STRING)
	@Column(name = "uncertain_reason", length = 64)
	private AlertUncertainReason uncertainReason;

	@Enumerated(EnumType.STRING)
	@Column(name = "matched_by", length = 32)
	private AlertMatchMethod matchedBy;

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

	public Alert(
			SoftwareInstall softwareInstall,
			Vulnerability vulnerability,
			LocalDateTime detectedAt,
			AlertCertainty certainty,
			AlertUncertainReason uncertainReason,
			AlertMatchMethod matchedBy
	) {
		this.softwareInstall = softwareInstall;
		this.vulnerability = vulnerability;
		this.firstSeenAt = detectedAt;
		this.lastSeenAt = detectedAt;
		this.status = AlertStatus.OPEN;

		this.certainty = (certainty == null ? AlertCertainty.CONFIRMED : certainty);
		this.uncertainReason = (this.certainty == AlertCertainty.UNCONFIRMED ? uncertainReason : null);
		this.matchedBy = matchedBy;
	}

	public void touchDetected(LocalDateTime detectedAt) {
		this.lastSeenAt = detectedAt;
	}

	/**
	 * 最新判定で確度が更新できるようにする（例: UNCONFIRMED → CONFIRMED への自動昇格）
	 */
	public void updateMatchContext(AlertCertainty certainty, AlertUncertainReason reason, AlertMatchMethod matchedBy) {
		AlertCertainty safe = (certainty == null ? AlertCertainty.CONFIRMED : certainty);
		this.certainty = safe;
		this.uncertainReason = (safe == AlertCertainty.UNCONFIRMED ? reason : null);
		this.matchedBy = matchedBy;
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
		if (this.certainty == null) this.certainty = AlertCertainty.CONFIRMED;

		if (this.certainty != AlertCertainty.UNCONFIRMED) {
			this.uncertainReason = null;
		}
	}

	@PreUpdate
	void preUpdate() {
		this.updatedAt = LocalDateTime.now();
		if (this.status == null) this.status = AlertStatus.OPEN;
		if (this.certainty == null) this.certainty = AlertCertainty.CONFIRMED;

		if (this.certainty != AlertCertainty.UNCONFIRMED) {
			this.uncertainReason = null;
		}
	}
}