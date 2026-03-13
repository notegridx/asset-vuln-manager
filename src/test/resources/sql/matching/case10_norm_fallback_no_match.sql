INSERT INTO vulnerabilities (
    id, source, external_id, title, description,
    severity, cvss_version, cvss_score
) VALUES
    (2010, 'NVD', 'CVE-2099-0010', 'CASE-10', 'norm fallback no match', 'HIGH', '3.1', 7.5);

INSERT INTO software_installs (
    id, asset_id, type, source,
    vendor_raw, product_raw, version_raw,
    vendor, product, version,
    normalized_vendor, normalized_product,
    cpe_vendor_id, cpe_product_id,
    source_type, canonical_link_disabled
) VALUES
    (3010, 1, 'APPLICATION', 'MANUAL',
     'Acme Corp.', 'Widget App Far', '9.9',
     'Acme Corp.', 'Widget App Far', '9.9',
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
    (4010, 2010, 'cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*',
     NULL, NULL,
     'acme', 'widget',
     '1.0', '', '5.0', '',
     'case10');