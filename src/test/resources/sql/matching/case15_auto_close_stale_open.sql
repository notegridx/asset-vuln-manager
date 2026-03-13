INSERT INTO vulnerabilities (
    id, source, external_id, title, description,
    severity, cvss_version, cvss_score
) VALUES
    (2015, 'NVD', 'CVE-2099-0015', 'CASE-15', 'auto close stale open', 'HIGH', '3.1', 8.1);

INSERT INTO software_installs (
    id, asset_id, type, source,
    vendor_raw, product_raw, version_raw,
    vendor, product, version,
    normalized_vendor, normalized_product,
    cpe_vendor_id, cpe_product_id,
    source_type, canonical_link_disabled
) VALUES
    (3015, 1, 'APPLICATION', 'MANUAL',
     'Acme', 'Widget AutoClose', '20.0',
     'Acme', 'Widget AutoClose', '20.0',
     'acme', 'widget',
     101, 1001,
     'UNKNOWN', FALSE);

INSERT INTO vulnerability_affected_cpes (
    id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    dedupe_key
) VALUES
    (4015, 2015, 'cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*',
     101, 1001,
     'acme', 'widget',
     '1.0', '', '2.0', '',
     'case15');

INSERT INTO alerts (
    id, software_install_id, vulnerability_id,
    status, certainty, uncertain_reason, matched_by,
    close_reason, first_seen_at, last_seen_at, closed_at,
    snapshot_asset_id, snapshot_asset_name, snapshot_external_key,
    snapshot_software_install_id, snapshot_vendor, snapshot_product, snapshot_version
) VALUES
    (
        5003, 3015, 2015,
        'OPEN', 'CONFIRMED', NULL, 'DICT_ID',
        NULL,
        '2026-03-01 00:00:00.000000',
        '2026-03-01 00:00:00.000000',
        NULL,
        1, 'Case Host 01', 'asset-case-host-01',
        3015, 'Acme', 'Widget AutoClose', '20.0'
    );