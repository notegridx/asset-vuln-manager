UPDATE assets
SET platform = 'mac',
    os_name = 'macOS Sonoma'
WHERE id = 1;

INSERT INTO cpe_vendors (
    id, name_norm, display_name, source
) VALUES
    (128, 'vendor28', 'Vendor28', 'TEST');

INSERT INTO cpe_products (
    id, vendor_id, name_norm, display_name, source
) VALUES
    (1038, 128, 'appa28', 'AppA28', 'TEST');

INSERT INTO vulnerabilities (
    id, source, external_id, title, description,
    severity, cvss_version, cvss_score
) VALUES
    (2028, 'NVD', 'CVE-2099-0028', 'CASE-28', 'windows-only leaf', 'MEDIUM', '3.1', 6.9);

INSERT INTO software_installs (
    id, asset_id, type, source,
    vendor_raw, product_raw, version_raw,
    vendor, product, version,
    normalized_vendor, normalized_product,
    cpe_vendor_id, cpe_product_id,
    source_type, canonical_link_disabled
) VALUES
    (3031, 1, 'APPLICATION', 'MANUAL',
     'Vendor28', 'AppA28', '8.1',
     'Vendor28', 'AppA28', '8.1',
     'vendor28', 'appa28',
     128, 1038,
     'UNKNOWN', FALSE);

INSERT INTO vulnerability_criteria_nodes (
    id, vulnerability_id, parent_id, root_group_no,
    node_type, operator, negate, sort_order
) VALUES
    (5091, 2028, NULL, 0, 'LEAF_GROUP', NULL, FALSE, 0);

INSERT INTO vulnerability_criteria_cpes (
    id, node_id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    match_vulnerable, dedupe_key
) VALUES
    (6091, 5091, 2028, 'cpe:2.3:a:vendor28:appa28:*:*:*:*:*:windows:*:*',
     128, 1038,
     'vendor28', 'appa28',
     'a', 'windows', '*',
     '8.0', '', '9.0', '',
     TRUE, 'case28-crit-a');

INSERT INTO vulnerability_affected_cpes (
    id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    criteria_node_id, root_group_no, dedupe_key
) VALUES
    (40281, 2028, 'cpe:2.3:a:vendor28:appa28:*:*:*:*:*:windows:*:*',
     128, 1038,
     'vendor28', 'appa28',
     'a', 'windows', '*',
     '8.0', '', '9.0', '',
     5091, 0, 'case28-flat-a');