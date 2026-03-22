INSERT INTO vulnerabilities (
    id, source, external_id, description,
    severity, cvss_version, cvss_score
) VALUES
    (2007, 'NVD', 'CVE-2099-0007',  'missing software version', 'MEDIUM', '3.1', 6.0);

INSERT INTO software_installs (
    id, asset_id, type, source,
    vendor_raw, product_raw, version_raw,
    vendor, product, version,
    normalized_vendor, normalized_product,
    cpe_vendor_id, cpe_product_id,
    source_type, canonical_link_disabled
) VALUES
    (3007, 1, 'APPLICATION', 'MANUAL',
     'Acme', 'Widget', '',
     'Acme', 'Widget', '',
     'acme', 'widget',
     101, 1001,
     'UNKNOWN', FALSE);

INSERT INTO vulnerability_affected_cpes (
    id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    dedupe_key
) VALUES
    (4007, 2007, 'cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*',
     101, 1001,
     'acme', 'widget',
     'a', '*', '*',
     '1.0.0', '', '2.0.0', '',
     'case07');