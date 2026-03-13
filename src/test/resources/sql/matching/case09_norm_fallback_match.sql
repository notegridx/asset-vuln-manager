INSERT INTO vulnerabilities (
    id, source, external_id, title, description,
    severity, cvss_version, cvss_score
) VALUES
    (2009, 'NVD', 'CVE-2099-0009', 'CASE-09', 'norm fallback match', 'HIGH', '3.1', 7.5);

INSERT INTO software_installs (
    id, asset_id, type, source,
    vendor_raw, product_raw, version_raw,
    vendor, product, version,
    normalized_vendor, normalized_product,
    cpe_vendor_id, cpe_product_id,
    source_type, canonical_link_disabled
) VALUES
    (3009, 1, 'APPLICATION', 'MANUAL',
     'Acme Corp.', 'Widget App', '4.5',
     'Acme Corp.', 'Widget App', '4.5',
     'acme', 'widget',
     NULL, NULL,
     'UNKNOWN', FALSE);

INSERT INTO vulnerability_affected_cpes (
    id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    dedupe_key
) VALUES
    (4009, 2009, 'cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*',
     NULL, NULL,
     'acme', 'widget',
     '4.0', '', '5.0', '',
     'case09');