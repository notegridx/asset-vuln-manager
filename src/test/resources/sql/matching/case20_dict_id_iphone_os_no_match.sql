UPDATE assets
SET platform = 'windows',
    os_name = 'Windows 11'
WHERE id = 1;

INSERT INTO cpe_vendors (
    id, name_norm, display_name, source
) VALUES
    (120, 'mozilla', 'Mozilla', 'TEST');

INSERT INTO cpe_products (
    id, vendor_id, name_norm, display_name, source
) VALUES
    (1020, 120, 'firefox', 'Firefox', 'TEST');

INSERT INTO vulnerabilities (
    id, source, external_id, title, description,
    severity, cvss_version, cvss_score
) VALUES
    (2020, 'NVD', 'CVE-2099-0020', 'CASE-20', 'firefox iphone only', 'HIGH', '3.1', 8.1);

INSERT INTO software_installs (
    id, asset_id, type, source,
    vendor_raw, product_raw, version_raw,
    vendor, product, version,
    normalized_vendor, normalized_product,
    cpe_vendor_id, cpe_product_id,
    source_type, canonical_link_disabled
) VALUES
    (3020, 1, 'APPLICATION', 'MANUAL',
     'Mozilla', 'Firefox', '120.0',
     'Mozilla', 'Firefox', '120.0',
     'mozilla', 'firefox',
     120, 1020,
     'UNKNOWN', FALSE);

INSERT INTO vulnerability_affected_cpes (
    id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    dedupe_key
) VALUES
    (4020, 2020, 'cpe:2.3:a:mozilla:firefox:*:*:*:*:*:iphone_os:*:*',
     120, 1020,
     'mozilla', 'firefox',
     '119.0', '', '121.0', '',
     'case20');