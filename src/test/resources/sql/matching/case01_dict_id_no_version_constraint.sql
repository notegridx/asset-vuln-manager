INSERT INTO vulnerabilities (
    id, source, external_id, title, description,
    severity, cvss_version, cvss_score
) VALUES
    (2001, 'NVD', 'CVE-2099-0001', 'CASE-01', 'DICT_ID + no range', 'MEDIUM', '3.1', 5.0);

INSERT INTO software_installs (
    id, asset_id, type, source,
    vendor_raw, product_raw, version_raw,
    vendor, product, version,
    normalized_vendor, normalized_product,
    cpe_vendor_id, cpe_product_id,
    source_type, canonical_link_disabled
) VALUES
    (3001, 1, 'APPLICATION', 'MANUAL',
     'Acme', 'Widget', '5.0',
     'Acme', 'Widget', '5.0',
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
    (4001, 2001, 'cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*',
     101, 1001,
     'acme', 'widget',
     '', '', '', '',
     'case01');