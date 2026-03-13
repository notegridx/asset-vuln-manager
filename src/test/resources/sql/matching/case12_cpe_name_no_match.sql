INSERT INTO vulnerabilities (
    id, source, external_id, title, description,
    severity, cvss_version, cvss_score
) VALUES
    (2012, 'NVD', 'CVE-2099-0012', 'CASE-12', 'cpe_name no match', 'CRITICAL', '3.1', 9.8);

INSERT INTO software_installs (
    id, asset_id, type, source,
    vendor_raw, product_raw, version_raw,
    vendor, product, version,
    normalized_vendor, normalized_product,
    cpe_vendor_id, cpe_product_id,
    cpe_name,
    source_type, canonical_link_disabled
) VALUES
    (3012, 1, 'APPLICATION', 'MANUAL',
     'Unknown Vendor', 'Unknown Product 99', '99.0',
     'Unknown Vendor', 'Unknown Product 99', '99.0',
     'unknown_vendor', 'unknown_product',
     NULL, NULL,
     'cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*',
     'UNKNOWN', FALSE);

INSERT INTO vulnerability_affected_cpes (
    id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    dedupe_key
) VALUES
    (4012, 2012, 'cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*',
     NULL, NULL,
     NULL, NULL,
     '1.0', '', '8.0', '',
     'case12');