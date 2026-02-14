CREATE TABLE IF NOT EXISTS assets
(
    id
    BIGINT
    GENERATED
    BY
    DEFAULT AS
    IDENTITY
    PRIMARY
    KEY,
    external_key
    VARCHAR
(
    128
),
    name VARCHAR
(
    255
) NOT NULL,
    asset_type VARCHAR
(
    32
),
    owner VARCHAR
(
    255
),
    note CLOB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT uq_assets_external_key UNIQUE
(
    external_key
)
    );

CREATE TABLE IF NOT EXISTS software_installs
(
    id
    BIGINT
    GENERATED
    BY
    DEFAULT AS
    IDENTITY
    PRIMARY
    KEY,
    asset_id
    BIGINT
    NOT
    NULL,
    vendor
    VARCHAR
(
    255
),
    product VARCHAR
(
    255
) NOT NULL,
    version VARCHAR
(
    64
),
    cpe_name VARCHAR
(
    512
),
    normalized_vendor VARCHAR
(
    255
),
    normalized_product VARCHAR
(
    255
),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT fk_sw_asset FOREIGN KEY
(
    asset_id
) REFERENCES assets
(
    id
),
    CONSTRAINT uq_sw_asset_vendor_product_version UNIQUE
(
    asset_id,
    vendor,
    product,
    version
)
    );

CREATE INDEX IF NOT EXISTS idx_sw_asset_id ON software_installs(asset_id);
CREATE INDEX IF NOT EXISTS idx_sw_cpe ON software_installs(cpe_name);
CREATE INDEX IF NOT EXISTS idx_sw_norm ON software_installs(normalized_vendor, normalized_product);

CREATE TABLE IF NOT EXISTS vulnerabilities
(
    id
    BIGINT
    GENERATED
    BY
    DEFAULT AS
    IDENTITY
    PRIMARY
    KEY,
    source
    VARCHAR
(
    32
) NOT NULL,
    external_id VARCHAR
(
    64
) NOT NULL,
    title VARCHAR
(
    512
),
    description CLOB,
    severity VARCHAR
(
    16
) NOT NULL,
    cvss_version VARCHAR
(
    16
),
    cvss_score DECIMAL
(
    4,
    1
),
    published_at TIMESTAMP,
    last_modified_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT uq_vuln_source_external UNIQUE
(
    source,
    external_id
)
    );

CREATE TABLE IF NOT EXISTS vulnerability_affected_cpes
(
    id
    BIGINT
    GENERATED
    BY
    DEFAULT AS
    IDENTITY
    PRIMARY
    KEY,
    vulnerability_id
    BIGINT
    NOT
    NULL,
    cpe_name
    VARCHAR
(
    512
) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT fk_vac_vuln FOREIGN KEY
(
    vulnerability_id
) REFERENCES vulnerabilities
(
    id
),
    CONSTRAINT uq_vuln_cpe UNIQUE
(
    vulnerability_id,
    cpe_name
)
    );

CREATE INDEX IF NOT EXISTS idx_vac_cpe ON vulnerability_affected_cpes(cpe_name);
CREATE INDEX IF NOT EXISTS idx_vac_vuln ON vulnerability_affected_cpes(vulnerability_id);

CREATE TABLE IF NOT EXISTS alerts
(
    id
    BIGINT
    GENERATED
    BY
    DEFAULT AS
    IDENTITY
    PRIMARY
    KEY,
    software_install_id
    BIGINT
    NOT
    NULL,
    vulnerability_id
    BIGINT
    NOT
    NULL,
    status
    VARCHAR
(
    16
) NOT NULL,
    close_reason VARCHAR
(
    255
),
    first_seen_at TIMESTAMP NOT NULL,
    last_seen_at TIMESTAMP NOT NULL,
    closed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    CONSTRAINT fk_alert_sw FOREIGN KEY
(
    software_install_id
) REFERENCES software_installs
(
    id
),
    CONSTRAINT fk_alert_vuln FOREIGN KEY
(
    vulnerability_id
) REFERENCES vulnerabilities
(
    id
),
    CONSTRAINT uq_alert_pair UNIQUE
(
    software_install_id,
    vulnerability_id
)
    );

CREATE INDEX IF NOT EXISTS idx_alert_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alert_vuln ON alerts(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_alert_sw ON alerts(software_install_id);