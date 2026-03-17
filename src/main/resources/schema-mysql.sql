-- =========================================================
-- schema-mysql.sql (MySQL 8.x) - Normal use (repeat-safe)
-- Spring Boot sql.init can execute this on every startup.
-- =========================================================

SET NAMES utf8mb4;

-- =========================================================
-- helper: safe create index
-- =========================================================
-- Pattern:
-- SET @ddl = IF(
--   EXISTS(
--     SELECT 1
--       FROM information_schema.statistics
--      WHERE table_schema = DATABASE()
--        AND table_name = '...'
--        AND index_name = '...'
--   ),
--   'SELECT 1',
--   'CREATE INDEX ... ON ...(...)'
-- );
-- PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- =========================================================
-- Assets
-- =========================================================

CREATE TABLE IF NOT EXISTS assets
(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    external_key VARCHAR(128),
    name VARCHAR(255) NOT NULL,
    asset_type VARCHAR(32),
    owner VARCHAR(255),
    note TEXT,

    -- inventory ingestion (osquery/fleet/wazuh/manual)
    source VARCHAR(32) NOT NULL DEFAULT 'MANUAL',
    -- optional: platform hint (windows/linux/darwin)
    platform VARCHAR(32),
    -- optional: OS display hint (free-form)
    os_version VARCHAR(128),

    -- ===== Added: identity / hardware / OS details (osquery-friendly) =====
    system_uuid VARCHAR(128),
    serial_number VARCHAR(128),

    hardware_vendor VARCHAR(255),
    hardware_model VARCHAR(255),
    hardware_version VARCHAR(255),

    computer_name VARCHAR(255),
    local_hostname VARCHAR(255),
    hostname VARCHAR(255),

    cpu_brand VARCHAR(255),
    cpu_physical_cores INT,
    cpu_logical_cores INT,
    cpu_sockets INT,
    physical_memory BIGINT,
    arch VARCHAR(64),

    board_vendor VARCHAR(255),
    board_model VARCHAR(255),
    board_version VARCHAR(255),
    board_serial VARCHAR(255),

    os_name VARCHAR(128),
    os_build VARCHAR(128),
    os_major INT,
    os_minor INT,
    os_patch INT,

    -- snapshot observation timestamp
    last_seen_at TIMESTAMP(6) NULL,

    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    CONSTRAINT uq_assets_external_key UNIQUE (external_key)
    ) ENGINE=InnoDB;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'assets'
           AND index_name = 'idx_assets_external_key'
    ),
    'SELECT 1',
    'CREATE INDEX idx_assets_external_key ON assets(external_key)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'assets'
           AND index_name = 'idx_assets_source'
    ),
    'SELECT 1',
    'CREATE INDEX idx_assets_source ON assets(source)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'assets'
           AND index_name = 'idx_assets_last_seen'
    ),
    'SELECT 1',
    'CREATE INDEX idx_assets_last_seen ON assets(last_seen_at)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'assets'
           AND index_name = 'idx_assets_system_uuid'
    ),
    'SELECT 1',
    'CREATE INDEX idx_assets_system_uuid ON assets(system_uuid)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'assets'
           AND index_name = 'idx_assets_serial_number'
    ),
    'SELECT 1',
    'CREATE INDEX idx_assets_serial_number ON assets(serial_number)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'assets'
           AND index_name = 'idx_assets_local_hostname'
    ),
    'SELECT 1',
    'CREATE INDEX idx_assets_local_hostname ON assets(local_hostname)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'assets'
           AND index_name = 'idx_assets_platform'
    ),
    'SELECT 1',
    'CREATE INDEX idx_assets_platform ON assets(platform)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- =========================================================
-- CPE Dictionary (vendors/products)
-- =========================================================

CREATE TABLE IF NOT EXISTS cpe_vendors
(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name_norm VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    source VARCHAR(20) NOT NULL DEFAULT 'CPE_DICT',
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_cpe_vendors_name UNIQUE (name_norm)
    ) ENGINE=InnoDB;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'cpe_vendors'
           AND index_name = 'idx_cpe_vendors_name'
    ),
    'SELECT 1',
    'CREATE INDEX idx_cpe_vendors_name ON cpe_vendors(name_norm)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS cpe_products
(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    vendor_id BIGINT NOT NULL,
    name_norm VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    source VARCHAR(20) NOT NULL DEFAULT 'CPE_DICT',
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_cpe_products_vendor FOREIGN KEY (vendor_id) REFERENCES cpe_vendors(id),
    CONSTRAINT uq_cpe_products_vendor_name UNIQUE (vendor_id, name_norm)
    ) ENGINE=InnoDB;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'cpe_products'
           AND index_name = 'idx_cpe_products_vendor'
    ),
    'SELECT 1',
    'CREATE INDEX idx_cpe_products_vendor ON cpe_products(vendor_id)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'cpe_products'
           AND index_name = 'idx_cpe_products_name'
    ),
    'SELECT 1',
    'CREATE INDEX idx_cpe_products_name ON cpe_products(name_norm)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'cpe_products'
           AND index_name = 'idx_cpe_products_vendor_name'
    ),
    'SELECT 1',
    'CREATE INDEX idx_cpe_products_vendor_name ON cpe_products(vendor_id, name_norm)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- =========================================================
-- CPE Feed sync state
-- =========================================================

CREATE TABLE IF NOT EXISTS cpe_sync_state
(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    feed_name VARCHAR(64) NOT NULL,
    meta_sha256 VARCHAR(128),
    meta_last_modified VARCHAR(64),
    meta_size BIGINT,
    last_synced_at TIMESTAMP(6) NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_cpe_sync_state_feed UNIQUE (feed_name)
    ) ENGINE=InnoDB;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'cpe_sync_state'
           AND index_name = 'idx_cpe_sync_state_feed'
    ),
    'SELECT 1',
    'CREATE INDEX idx_cpe_sync_state_feed ON cpe_sync_state(feed_name)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- =========================================================
-- Import runs (inventory ingestion unit)
-- =========================================================

CREATE TABLE IF NOT EXISTS import_runs
(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    source VARCHAR(32) NOT NULL,
    kind VARCHAR(32) NOT NULL,
    started_at TIMESTAMP(6) NOT NULL,
    finished_at TIMESTAMP(6) NULL,
    file_hash VARCHAR(128),
    summary TEXT,
    assets_upserted INT NOT NULL DEFAULT 0,
    software_upserted INT NOT NULL DEFAULT 0,
    unresolved_count INT NOT NULL DEFAULT 0,
    error_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    status VARCHAR(16) NOT NULL DEFAULT 'IMPORTED',
    original_filename VARCHAR(255),
    sha256 VARCHAR(128),
    total_rows INT NOT NULL DEFAULT 0,
    valid_rows INT NOT NULL DEFAULT 0,
    invalid_rows INT NOT NULL DEFAULT 0,
    error_message VARCHAR(1024),

    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
    ) ENGINE=InnoDB;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'import_runs'
           AND index_name = 'idx_import_runs_started'
    ),
    'SELECT 1',
    'CREATE INDEX idx_import_runs_started ON import_runs(started_at)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'import_runs'
           AND index_name = 'idx_import_runs_source'
    ),
    'SELECT 1',
    'CREATE INDEX idx_import_runs_source ON import_runs(source)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'import_runs'
           AND index_name = 'idx_import_runs_status'
    ),
    'SELECT 1',
    'CREATE INDEX idx_import_runs_status ON import_runs(status)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- =========================================================
-- Admin Runs (generic job run history)
-- =========================================================

CREATE TABLE IF NOT EXISTS admin_runs
(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    job_type VARCHAR(64) NOT NULL,
    status VARCHAR(16) NOT NULL,

    started_at TIMESTAMP(6) NOT NULL,
    finished_at TIMESTAMP(6) NULL,
    duration_ms BIGINT,

    params_json TEXT,
    result_json TEXT,
    error_message TEXT,

    created_at TIMESTAMP(6) NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL
    ) ENGINE=InnoDB;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'admin_runs'
           AND index_name = 'idx_admin_runs_started_at'
    ),
    'SELECT 1',
    'CREATE INDEX idx_admin_runs_started_at ON admin_runs(started_at)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'admin_runs'
           AND index_name = 'idx_admin_runs_job_type'
    ),
    'SELECT 1',
    'CREATE INDEX idx_admin_runs_job_type ON admin_runs(job_type)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'admin_runs'
           AND index_name = 'idx_admin_runs_status'
    ),
    'SELECT 1',
    'CREATE INDEX idx_admin_runs_status ON admin_runs(status)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- =========================================================
-- Software inventory
-- =========================================================

CREATE TABLE IF NOT EXISTS software_installs
(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    asset_id BIGINT NOT NULL,

    type VARCHAR(32) NOT NULL DEFAULT 'APPLICATION',
    source VARCHAR(32) NOT NULL DEFAULT 'MANUAL',

    vendor_raw VARCHAR(255),
    product_raw VARCHAR(255),
    version_raw VARCHAR(128),

    vendor VARCHAR(255) NOT NULL DEFAULT '',
    product VARCHAR(255) NOT NULL,

    version VARCHAR(64) NOT NULL DEFAULT '',
    version_norm VARCHAR(128),

    cpe_name VARCHAR(512),

    normalized_vendor VARCHAR(255),
    normalized_product VARCHAR(255),

    cpe_vendor_id BIGINT,
    cpe_product_id BIGINT,

    last_seen_at TIMESTAMP(6) NULL,

    import_run_id BIGINT,

    install_location VARCHAR(1024),
    installed_at TIMESTAMP(6) NULL,
    package_identifier VARCHAR(255),
    arch VARCHAR(64),

    source_type VARCHAR(64) NOT NULL DEFAULT 'UNKNOWN',

    publisher VARCHAR(255),
    bundle_id VARCHAR(255),
    package_manager VARCHAR(64),
    install_source VARCHAR(64),

    edition VARCHAR(128),
    channel VARCHAR(64),
    release_label VARCHAR(128),

    purl VARCHAR(512),

    canonical_link_disabled BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    CONSTRAINT fk_sw_asset FOREIGN KEY (asset_id) REFERENCES assets(id),
    CONSTRAINT fk_sw_cpe_vendor FOREIGN KEY (cpe_vendor_id) REFERENCES cpe_vendors(id),
    CONSTRAINT fk_sw_cpe_product FOREIGN KEY (cpe_product_id) REFERENCES cpe_products(id),
    CONSTRAINT fk_sw_import_run FOREIGN KEY (import_run_id) REFERENCES import_runs(id),

    CONSTRAINT uq_sw_asset_vendor_product_version UNIQUE (asset_id, vendor, product, version)
    ) ENGINE=InnoDB;

SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'software_installs' AND index_name = 'idx_sw_asset_id'), 'SELECT 1', 'CREATE INDEX idx_sw_asset_id ON software_installs(asset_id)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'software_installs' AND index_name = 'idx_sw_cpe'), 'SELECT 1', 'CREATE INDEX idx_sw_cpe ON software_installs(cpe_name)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'software_installs' AND index_name = 'idx_sw_norm'), 'SELECT 1', 'CREATE INDEX idx_sw_norm ON software_installs(normalized_vendor, normalized_product)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'software_installs' AND index_name = 'idx_sw_type'), 'SELECT 1', 'CREATE INDEX idx_sw_type ON software_installs(type)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'software_installs' AND index_name = 'idx_sw_source'), 'SELECT 1', 'CREATE INDEX idx_sw_source ON software_installs(source)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'software_installs' AND index_name = 'idx_sw_source_type'), 'SELECT 1', 'CREATE INDEX idx_sw_source_type ON software_installs(source_type)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'software_installs' AND index_name = 'idx_sw_last_seen'), 'SELECT 1', 'CREATE INDEX idx_sw_last_seen ON software_installs(last_seen_at)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'software_installs' AND index_name = 'idx_sw_import_run'), 'SELECT 1', 'CREATE INDEX idx_sw_import_run ON software_installs(import_run_id)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'software_installs' AND index_name = 'idx_sw_pkg_identifier'), 'SELECT 1', 'CREATE INDEX idx_sw_pkg_identifier ON software_installs(package_identifier)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'software_installs' AND index_name = 'idx_sw_publisher'), 'SELECT 1', 'CREATE INDEX idx_sw_publisher ON software_installs(publisher)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'software_installs' AND index_name = 'idx_sw_bundle_id'), 'SELECT 1', 'CREATE INDEX idx_sw_bundle_id ON software_installs(bundle_id)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'software_installs' AND index_name = 'idx_sw_pkg_manager'), 'SELECT 1', 'CREATE INDEX idx_sw_pkg_manager ON software_installs(package_manager)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'software_installs' AND index_name = 'idx_sw_purl'), 'SELECT 1', 'CREATE INDEX idx_sw_purl ON software_installs(purl)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'software_installs' AND index_name = 'idx_sw_vendor_product_id'), 'SELECT 1', 'CREATE INDEX idx_sw_vendor_product_id ON software_installs(cpe_vendor_id, cpe_product_id)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'software_installs' AND index_name = 'idx_sw_asset_vendor_product_id'), 'SELECT 1', 'CREATE INDEX idx_sw_asset_vendor_product_id ON software_installs(asset_id, cpe_vendor_id, cpe_product_id)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- =========================================================
-- Staging tables for JSON Import (Upload -> Preview -> Import)
-- =========================================================

CREATE TABLE IF NOT EXISTS import_staging_assets
(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    import_run_id BIGINT NOT NULL,
    row_no INT NOT NULL,

    external_key VARCHAR(128),
    name VARCHAR(255),
    asset_type VARCHAR(32),
    owner VARCHAR(255),
    note TEXT,

    source VARCHAR(32),
    platform VARCHAR(32),
    os_version VARCHAR(128),

    system_uuid VARCHAR(128),
    serial_number VARCHAR(128),

    hardware_vendor VARCHAR(255),
    hardware_model VARCHAR(255),
    hardware_version VARCHAR(255),

    computer_name VARCHAR(255),
    local_hostname VARCHAR(255),
    hostname VARCHAR(255),

    cpu_brand VARCHAR(255),
    cpu_physical_cores INT,
    cpu_logical_cores INT,
    cpu_sockets INT,
    physical_memory BIGINT,
    arch VARCHAR(64),

    board_vendor VARCHAR(255),
    board_model VARCHAR(255),
    board_version VARCHAR(255),
    board_serial VARCHAR(255),

    os_name VARCHAR(128),
    os_build VARCHAR(128),
    os_major INT,
    os_minor INT,
    os_patch INT,

    last_seen_at TIMESTAMP(6) NULL,

    is_valid BOOLEAN NOT NULL DEFAULT TRUE,
    validation_error VARCHAR(1024),

    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    CONSTRAINT fk_stage_assets_run FOREIGN KEY (import_run_id) REFERENCES import_runs(id)
    ) ENGINE=InnoDB;

SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'import_staging_assets' AND index_name = 'idx_stage_assets_run'), 'SELECT 1', 'CREATE INDEX idx_stage_assets_run ON import_staging_assets(import_run_id)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'import_staging_assets' AND index_name = 'idx_stage_assets_key'), 'SELECT 1', 'CREATE INDEX idx_stage_assets_key ON import_staging_assets(external_key)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS import_staging_software
(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    import_run_id BIGINT NOT NULL,
    row_no INT NOT NULL,

    external_key VARCHAR(128),

    vendor VARCHAR(255),
    product VARCHAR(255),
    version VARCHAR(64),

    install_location VARCHAR(1024),
    installed_at TIMESTAMP(6) NULL,
    package_identifier VARCHAR(255),
    arch VARCHAR(64),

    source_type VARCHAR(64) NOT NULL DEFAULT 'JSON_UPLOAD',

    last_seen_at TIMESTAMP(6) NULL,

    type VARCHAR(32),
    source VARCHAR(32),

    vendor_raw VARCHAR(255),
    product_raw VARCHAR(255),
    version_raw VARCHAR(128),

    publisher VARCHAR(255),
    bundle_id VARCHAR(255),
    package_manager VARCHAR(64),
    install_source VARCHAR(64),

    edition VARCHAR(128),
    channel VARCHAR(64),
    release_label VARCHAR(128),

    purl VARCHAR(512),

    is_valid BOOLEAN NOT NULL DEFAULT TRUE,
    validation_error VARCHAR(1024),

    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    CONSTRAINT fk_stage_sw_run FOREIGN KEY (import_run_id) REFERENCES import_runs(id)
    ) ENGINE=InnoDB;

SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'import_staging_software' AND index_name = 'idx_stage_sw_run'), 'SELECT 1', 'CREATE INDEX idx_stage_sw_run ON import_staging_software(import_run_id)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'import_staging_software' AND index_name = 'idx_stage_sw_key'), 'SELECT 1', 'CREATE INDEX idx_stage_sw_key ON import_staging_software(external_key)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'import_staging_software' AND index_name = 'idx_stage_sw_product'), 'SELECT 1', 'CREATE INDEX idx_stage_sw_product ON import_staging_software(product)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- =========================================================
-- Vulnerabilities (CVE)
-- =========================================================

CREATE TABLE IF NOT EXISTS vulnerabilities
(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    source VARCHAR(32) NOT NULL DEFAULT 'NVD',
    external_id VARCHAR(64) NOT NULL,

    title VARCHAR(1024),
    description TEXT,

    severity VARCHAR(16),
    cvss_version VARCHAR(16),
    cvss_score DOUBLE,

    published_at TIMESTAMP(6) NULL,
    last_modified_at TIMESTAMP(6) NULL,

    -- ==============================
    -- KEV metadata
    -- ==============================
    kev_flag BOOLEAN DEFAULT FALSE NOT NULL,
    kev_date_added DATE,
    kev_due_date DATE,
    kev_ransomware_use VARCHAR(16),
    kev_updated_at TIMESTAMP(6) NULL,

    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    CONSTRAINT uq_vuln_source_external UNIQUE (source, external_id)
    ) ENGINE=InnoDB;

SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'vulnerabilities' AND index_name = 'idx_vuln_severity'), 'SELECT 1', 'CREATE INDEX idx_vuln_severity ON vulnerabilities(severity)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'vulnerabilities' AND index_name = 'idx_vuln_lastmod_id'), 'SELECT 1', 'CREATE INDEX idx_vuln_lastmod_id ON vulnerabilities(last_modified_at, id)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'vulnerabilities' AND index_name = 'idx_vuln_kev_flag'), 'SELECT 1', 'CREATE INDEX idx_vuln_kev_flag ON vulnerabilities(kev_flag)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- =========================================================
-- KEV sync state
-- =========================================================

CREATE TABLE IF NOT EXISTS kev_sync_state
(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    feed_name VARCHAR(64) NOT NULL,
    etag VARCHAR(255),
    last_modified VARCHAR(128),
    body_sha256 VARCHAR(128),
    body_size BIGINT,
    fetched_at TIMESTAMP(6) NULL,

    created_at TIMESTAMP(6) NOT NULL,
    updated_at TIMESTAMP(6) NOT NULL,

    CONSTRAINT uq_kev_sync_state_feed UNIQUE (feed_name)
    ) ENGINE=InnoDB;

SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'kev_sync_state' AND index_name = 'idx_kev_sync_state_feed'), 'SELECT 1', 'CREATE INDEX idx_kev_sync_state_feed ON kev_sync_state(feed_name)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- =========================================================
-- Vulnerability affected CPEs
-- =========================================================

CREATE TABLE IF NOT EXISTS vulnerability_affected_cpes
(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    vulnerability_id BIGINT NOT NULL,

    cpe_name VARCHAR(512) NOT NULL,

    cpe_vendor_id BIGINT,
    cpe_product_id BIGINT,

    vendor_norm VARCHAR(255),
    product_norm VARCHAR(255),

    cpe_part VARCHAR(8),
    target_sw VARCHAR(64),
    target_hw VARCHAR(64),

    version_start_including VARCHAR(255) NOT NULL DEFAULT '',
    version_start_excluding VARCHAR(255) NOT NULL DEFAULT '',
    version_end_including   VARCHAR(255) NOT NULL DEFAULT '',
    version_end_excluding   VARCHAR(255) NOT NULL DEFAULT '',

    criteria_node_id BIGINT NULL,
    root_group_no INT NOT NULL DEFAULT 0,

    dedupe_key CHAR(64),

    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    CONSTRAINT fk_vac_vuln
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id),

    CONSTRAINT fk_vac_cpe_vendor
    FOREIGN KEY (cpe_vendor_id) REFERENCES cpe_vendors(id),

    CONSTRAINT fk_vac_cpe_product
    FOREIGN KEY (cpe_product_id) REFERENCES cpe_products(id)

    ) ENGINE=InnoDB;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'vulnerability_affected_cpes'
           AND index_name = 'idx_vac_cpe'
    ),
    'SELECT 1',
    'CREATE INDEX idx_vac_cpe ON vulnerability_affected_cpes(cpe_name)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'vulnerability_affected_cpes'
           AND index_name = 'idx_vac_vuln'
    ),
    'SELECT 1',
    'CREATE INDEX idx_vac_vuln ON vulnerability_affected_cpes(vulnerability_id)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'vulnerability_affected_cpes'
           AND index_name = 'idx_vac_vendor_product_id'
    ),
    'SELECT 1',
    'CREATE INDEX idx_vac_vendor_product_id ON vulnerability_affected_cpes(cpe_vendor_id, cpe_product_id)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'vulnerability_affected_cpes'
           AND index_name = 'idx_vac_vendor_product_norm'
    ),
    'SELECT 1',
    'CREATE INDEX idx_vac_vendor_product_norm ON vulnerability_affected_cpes(vendor_norm, product_norm)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'vulnerability_affected_cpes'
           AND index_name = 'idx_vac_target_sw'
    ),
    'SELECT 1',
    'CREATE INDEX idx_vac_target_sw ON vulnerability_affected_cpes(target_sw)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'vulnerability_affected_cpes'
           AND index_name = 'idx_vac_criteria_node'
    ),
    'SELECT 1',
    'CREATE INDEX idx_vac_criteria_node ON vulnerability_affected_cpes(criteria_node_id)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'vulnerability_affected_cpes'
           AND index_name = 'idx_vac_vuln_root'
    ),
    'SELECT 1',
    'CREATE INDEX idx_vac_vuln_root ON vulnerability_affected_cpes(vulnerability_id, root_group_no)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'vulnerability_affected_cpes'
           AND index_name = 'uq_vac_dedupe_key'
    ),
    'SELECT 1',
    'CREATE UNIQUE INDEX uq_vac_dedupe_key ON vulnerability_affected_cpes(dedupe_key)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- =========================================================
-- Vulnerability criteria tree
-- =========================================================

CREATE TABLE IF NOT EXISTS vulnerability_criteria_nodes
(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    vulnerability_id BIGINT NOT NULL,
    parent_id BIGINT NULL,

    root_group_no INT NOT NULL DEFAULT 0,
    node_type VARCHAR(16) NOT NULL,
    operator VARCHAR(8) NULL,
    negate BOOLEAN NOT NULL DEFAULT FALSE,
    sort_order INT NOT NULL DEFAULT 0,

    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    CONSTRAINT fk_vcn_vuln
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id),

    CONSTRAINT fk_vcn_parent
    FOREIGN KEY (parent_id) REFERENCES vulnerability_criteria_nodes(id)

    ) ENGINE=InnoDB;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'vulnerability_criteria_nodes'
           AND index_name = 'idx_vcn_vuln_root'
    ),
    'SELECT 1',
    'CREATE INDEX idx_vcn_vuln_root ON vulnerability_criteria_nodes(vulnerability_id, root_group_no)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'vulnerability_criteria_nodes'
           AND index_name = 'idx_vcn_parent'
    ),
    'SELECT 1',
    'CREATE INDEX idx_vcn_parent ON vulnerability_criteria_nodes(parent_id)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'vulnerability_criteria_nodes'
           AND index_name = 'idx_vcn_vuln_type'
    ),
    'SELECT 1',
    'CREATE INDEX idx_vcn_vuln_type ON vulnerability_criteria_nodes(vulnerability_id, node_type)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS vulnerability_criteria_cpes
(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    node_id BIGINT NOT NULL,
    vulnerability_id BIGINT NOT NULL,

    cpe_name VARCHAR(512) NOT NULL,

    cpe_vendor_id BIGINT NULL,
    cpe_product_id BIGINT NULL,

    vendor_norm VARCHAR(255) NULL,
    product_norm VARCHAR(255) NULL,

    cpe_part VARCHAR(8) NULL,
    target_sw VARCHAR(64) NULL,
    target_hw VARCHAR(64) NULL,

    version_start_including VARCHAR(255) NOT NULL DEFAULT '',
    version_start_excluding VARCHAR(255) NOT NULL DEFAULT '',
    version_end_including   VARCHAR(255) NOT NULL DEFAULT '',
    version_end_excluding   VARCHAR(255) NOT NULL DEFAULT '',

    match_vulnerable BOOLEAN NOT NULL DEFAULT TRUE,
    dedupe_key CHAR(64) NULL,

    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    CONSTRAINT fk_vcc_node
    FOREIGN KEY (node_id) REFERENCES vulnerability_criteria_nodes(id),

    CONSTRAINT fk_vcc_vuln
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id),

    CONSTRAINT fk_vcc_vendor
    FOREIGN KEY (cpe_vendor_id) REFERENCES cpe_vendors(id),

    CONSTRAINT fk_vcc_product
    FOREIGN KEY (cpe_product_id) REFERENCES cpe_products(id)

    ) ENGINE=InnoDB;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'vulnerability_criteria_cpes'
           AND index_name = 'idx_vcc_vuln'
    ),
    'SELECT 1',
    'CREATE INDEX idx_vcc_vuln ON vulnerability_criteria_cpes(vulnerability_id)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'vulnerability_criteria_cpes'
           AND index_name = 'idx_vcc_node'
    ),
    'SELECT 1',
    'CREATE INDEX idx_vcc_node ON vulnerability_criteria_cpes(node_id)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'vulnerability_criteria_cpes'
           AND index_name = 'idx_vcc_vendor_product_id'
    ),
    'SELECT 1',
    'CREATE INDEX idx_vcc_vendor_product_id ON vulnerability_criteria_cpes(cpe_vendor_id, cpe_product_id)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'vulnerability_criteria_cpes'
           AND index_name = 'idx_vcc_vendor_product_norm'
    ),
    'SELECT 1',
    'CREATE INDEX idx_vcc_vendor_product_norm ON vulnerability_criteria_cpes(vendor_norm, product_norm)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'vulnerability_criteria_cpes'
           AND index_name = 'idx_vcc_cpe_name'
    ),
    'SELECT 1',
    'CREATE INDEX idx_vcc_cpe_name ON vulnerability_criteria_cpes(cpe_name)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'vulnerability_criteria_cpes'
           AND index_name = 'uq_vcc_dedupe_key'
    ),
    'SELECT 1',
    'CREATE UNIQUE INDEX uq_vcc_dedupe_key ON vulnerability_criteria_cpes(dedupe_key)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- =========================================================
-- Alerts
-- =========================================================

CREATE TABLE IF NOT EXISTS alerts
(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    software_install_id BIGINT,
    vulnerability_id BIGINT NOT NULL,

    status VARCHAR(16) NOT NULL,
    certainty VARCHAR(16) NOT NULL DEFAULT 'CONFIRMED',
    uncertain_reason VARCHAR(64),
    matched_by VARCHAR(32),

    close_reason VARCHAR(255),
    first_seen_at TIMESTAMP(6) NOT NULL,
    last_seen_at TIMESTAMP(6) NOT NULL,
    closed_at TIMESTAMP(6) NULL,

    snapshot_asset_id BIGINT,
    snapshot_asset_name VARCHAR(255),
    snapshot_external_key VARCHAR(128),
    snapshot_software_install_id BIGINT,
    snapshot_vendor VARCHAR(255),
    snapshot_product VARCHAR(255),
    snapshot_version VARCHAR(64),

    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    CONSTRAINT fk_alert_sw FOREIGN KEY (software_install_id) REFERENCES software_installs(id),
    CONSTRAINT fk_alert_vuln FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id),
    CONSTRAINT uq_alert_pair UNIQUE (software_install_id, vulnerability_id)
    ) ENGINE=InnoDB;

SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'alerts' AND index_name = 'idx_alert_status'), 'SELECT 1', 'CREATE INDEX idx_alert_status ON alerts(status)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'alerts' AND index_name = 'idx_alert_certainty'), 'SELECT 1', 'CREATE INDEX idx_alert_certainty ON alerts(certainty)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'alerts' AND index_name = 'idx_alert_vuln'), 'SELECT 1', 'CREATE INDEX idx_alert_vuln ON alerts(vulnerability_id)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'alerts' AND index_name = 'idx_alert_sw'), 'SELECT 1', 'CREATE INDEX idx_alert_sw ON alerts(software_install_id)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'alerts' AND index_name = 'idx_alert_status_certainty'), 'SELECT 1', 'CREATE INDEX idx_alert_status_certainty ON alerts(status, certainty)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'alerts' AND index_name = 'idx_alert_vuln_status'), 'SELECT 1', 'CREATE INDEX idx_alert_vuln_status ON alerts(vulnerability_id, status)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- =========================================================
-- CVE feed sync state (NVD CVE JSON 2.0 feeds)
-- =========================================================

CREATE TABLE IF NOT EXISTS cve_sync_state
(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    feed_name VARCHAR(64) NOT NULL,

    meta_sha256 VARCHAR(128),
    meta_last_modified VARCHAR(64),
    meta_size BIGINT,

    last_synced_at TIMESTAMP(6) NULL,

    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    CONSTRAINT uq_cve_sync_state_feed UNIQUE (feed_name)
    ) ENGINE=InnoDB;

SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'cve_sync_state' AND index_name = 'idx_cve_sync_state_feed'), 'SELECT 1', 'CREATE INDEX idx_cve_sync_state_feed ON cve_sync_state(feed_name)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- =========================================================
-- Unresolved mappings (dictionary training queue)
-- =========================================================

CREATE TABLE IF NOT EXISTS unresolved_mappings
(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    source VARCHAR(32) NOT NULL,

    vendor_raw VARCHAR(255) NOT NULL,
    product_raw VARCHAR(255) NOT NULL,
    version_raw VARCHAR(128),

    normalized_vendor VARCHAR(255),
    normalized_product VARCHAR(255),

    candidate_vendor_ids VARCHAR(512),
    candidate_product_ids VARCHAR(512),

    status VARCHAR(16) NOT NULL DEFAULT 'NEW',
    note VARCHAR(1024),

    first_seen_at TIMESTAMP(6) NOT NULL,
    last_seen_at TIMESTAMP(6) NOT NULL,

    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    CONSTRAINT uk_um_vendor_product UNIQUE (vendor_raw, product_raw)
    ) ENGINE=InnoDB;

SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'unresolved_mappings' AND index_name = 'idx_um_status'), 'SELECT 1', 'CREATE INDEX idx_um_status ON unresolved_mappings(status)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'unresolved_mappings' AND index_name = 'idx_um_norm'), 'SELECT 1', 'CREATE INDEX idx_um_norm ON unresolved_mappings(normalized_vendor, normalized_product)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'unresolved_mappings' AND index_name = 'idx_um_vendor_product'), 'SELECT 1', 'CREATE INDEX idx_um_vendor_product ON unresolved_mappings(vendor_raw, product_raw)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- =========================================================
-- Synonyms / Aliases (dictionary learning)  [ID-based]
-- =========================================================

CREATE TABLE IF NOT EXISTS cpe_vendor_aliases
(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    alias_norm VARCHAR(255) NOT NULL,

    cpe_vendor_id BIGINT NOT NULL,

    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE',
    note VARCHAR(1024),

    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    source VARCHAR(32) NOT NULL DEFAULT 'MANUAL',
    confidence INT NOT NULL DEFAULT 0,
    evidence_url VARCHAR(1024),
    review_state VARCHAR(16) NOT NULL DEFAULT 'MANUAL',

    CONSTRAINT fk_vendor_alias_vendor FOREIGN KEY (cpe_vendor_id) REFERENCES cpe_vendors(id),
    CONSTRAINT uq_vendor_alias UNIQUE (alias_norm)
    ) ENGINE=InnoDB;

SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'cpe_vendor_aliases' AND index_name = 'idx_vendor_alias_vendor'), 'SELECT 1', 'CREATE INDEX idx_vendor_alias_vendor ON cpe_vendor_aliases(cpe_vendor_id)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'cpe_vendor_aliases' AND index_name = 'idx_vendor_alias_status'), 'SELECT 1', 'CREATE INDEX idx_vendor_alias_status ON cpe_vendor_aliases(status)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS cpe_product_aliases
(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,

    cpe_vendor_id BIGINT NOT NULL,

    alias_norm VARCHAR(255) NOT NULL,

    cpe_product_id BIGINT NOT NULL,

    status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE',
    note VARCHAR(1024),

    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    source VARCHAR(32) NOT NULL DEFAULT 'MANUAL',
    confidence INT NOT NULL DEFAULT 0,
    evidence_url VARCHAR(1024),
    review_state VARCHAR(16) NOT NULL DEFAULT 'MANUAL',

    CONSTRAINT fk_product_alias_vendor  FOREIGN KEY (cpe_vendor_id) REFERENCES cpe_vendors(id),
    CONSTRAINT fk_product_alias_product FOREIGN KEY (cpe_product_id) REFERENCES cpe_products(id),
    CONSTRAINT uq_product_alias UNIQUE (cpe_vendor_id, alias_norm)
    ) ENGINE=InnoDB;

SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'cpe_product_aliases' AND index_name = 'idx_product_alias_vendor'), 'SELECT 1', 'CREATE INDEX idx_product_alias_vendor ON cpe_product_aliases(cpe_vendor_id)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'cpe_product_aliases' AND index_name = 'idx_product_alias_product'), 'SELECT 1', 'CREATE INDEX idx_product_alias_product ON cpe_product_aliases(cpe_product_id)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'cpe_product_aliases' AND index_name = 'idx_product_alias_status'), 'SELECT 1', 'CREATE INDEX idx_product_alias_status ON cpe_product_aliases(status)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- =========================================================
-- Alias metadata extension (Top20 auto-seeding)
-- =========================================================
-- H2 版では ALTER TABLE ... ADD COLUMN IF NOT EXISTS で後付けしているが、
-- MySQL repeat-safe 版では CREATE TABLE に最初から含める。
-- ここでは対応する index だけ repeat-safe に作る。

SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'cpe_vendor_aliases' AND index_name = 'idx_cpe_vendor_aliases_review_state'), 'SELECT 1', 'CREATE INDEX idx_cpe_vendor_aliases_review_state ON cpe_vendor_aliases(review_state)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'cpe_vendor_aliases' AND index_name = 'idx_cpe_vendor_aliases_source'), 'SELECT 1', 'CREATE INDEX idx_cpe_vendor_aliases_source ON cpe_vendor_aliases(source)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'cpe_product_aliases' AND index_name = 'idx_cpe_product_aliases_review_state'), 'SELECT 1', 'CREATE INDEX idx_cpe_product_aliases_review_state ON cpe_product_aliases(review_state)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'cpe_product_aliases' AND index_name = 'idx_cpe_product_aliases_source'), 'SELECT 1', 'CREATE INDEX idx_cpe_product_aliases_source ON cpe_product_aliases(source)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;
SET @ddl = IF (EXISTS (SELECT 1 FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'cpe_product_aliases' AND index_name = 'idx_cpe_product_aliases_vendor_id'), 'SELECT 1', 'CREATE INDEX idx_cpe_product_aliases_vendor_id ON cpe_product_aliases(cpe_vendor_id)');
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- =========================================================
-- Security / Users / Roles
-- =========================================================

CREATE TABLE IF NOT EXISTS app_users
(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    account_non_locked BOOLEAN NOT NULL DEFAULT TRUE,
    password_change_required BOOLEAN NOT NULL DEFAULT FALSE,
    bootstrap_admin BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_app_users_username UNIQUE (username)
    ) ENGINE=InnoDB;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'app_users'
           AND index_name = 'idx_app_users_username'
    ),
    'SELECT 1',
    'CREATE INDEX idx_app_users_username ON app_users(username)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS app_roles
(
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(50) NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_app_roles_name UNIQUE (role_name)
    ) ENGINE=InnoDB;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'app_roles'
           AND index_name = 'idx_app_roles_name'
    ),
    'SELECT 1',
    'CREATE INDEX idx_app_roles_name ON app_roles(role_name)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

CREATE TABLE IF NOT EXISTS app_user_roles
(
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),

    CONSTRAINT pk_app_user_roles PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_app_user_roles_user FOREIGN KEY (user_id) REFERENCES app_users(id),
    CONSTRAINT fk_app_user_roles_role FOREIGN KEY (role_id) REFERENCES app_roles(id)
    ) ENGINE=InnoDB;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'app_user_roles'
           AND index_name = 'idx_app_user_roles_user'
    ),
    'SELECT 1',
    'CREATE INDEX idx_app_user_roles_user ON app_user_roles(user_id)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @ddl = IF (
    EXISTS (
        SELECT 1 FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'app_user_roles'
           AND index_name = 'idx_app_user_roles_role'
    ),
    'SELECT 1',
    'CREATE INDEX idx_app_user_roles_role ON app_user_roles(role_id)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;

INSERT IGNORE INTO app_roles (role_name) VALUES ('ADMIN');
INSERT IGNORE INTO app_roles (role_name) VALUES ('OPERATOR');
INSERT IGNORE INTO app_roles (role_name) VALUES ('VIEWER');

-- =========================================================
-- System Settings
-- =========================================================

CREATE TABLE IF NOT EXISTS system_settings
(
    setting_key VARCHAR(128) NOT NULL PRIMARY KEY,
    setting_value VARCHAR(2048) NOT NULL,
    updated_by VARCHAR(100) NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
    ) ENGINE=InnoDB;

SET @ddl = IF (
    EXISTS (
        SELECT 1
          FROM information_schema.statistics
         WHERE table_schema = DATABASE()
           AND table_name = 'system_settings'
           AND index_name = 'idx_system_settings_updated_at'
    ),
    'SELECT 1',
    'CREATE INDEX idx_system_settings_updated_at ON system_settings(updated_at)'
);
PREPARE stmt FROM @ddl; EXECUTE stmt; DEALLOCATE PREPARE stmt;