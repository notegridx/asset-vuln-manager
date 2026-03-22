UPDATE assets
SET platform = 'windows',
    os_name = 'Windows 11'
WHERE id = 1;

INSERT INTO cpe_vendors (
    id, name_norm, display_name, source
) VALUES
    (124, 'vendor24', 'Vendor24', 'TEST');

INSERT INTO cpe_products (
    id, vendor_id, name_norm, display_name, source
) VALUES
      (1028, 124, 'appa24', 'AppA24', 'TEST'),
      (1029, 124, 'appb24', 'AppB24', 'TEST');

INSERT INTO vulnerabilities (
    id, source, external_id, description,
    severity, cvss_version, cvss_score
) VALUES
    (2024, 'NVD', 'CVE-2099-0024',  'A AND B', 'CRITICAL', '3.1', 9.1);

INSERT INTO software_installs (
    id, asset_id, type, source,
    vendor_raw, product_raw, version_raw,
    vendor, product, version,
    normalized_vendor, normalized_product,
    cpe_vendor_id, cpe_product_id,
    source_type, canonical_link_disabled
) VALUES
      (3024, 1, 'APPLICATION', 'MANUAL',
       'Vendor24', 'AppA24', '3.5',
       'Vendor24', 'AppA24', '3.5',
       'vendor24', 'appa24',
       124, 1028,
       'UNKNOWN', FALSE),
      (3025, 1, 'APPLICATION', 'MANUAL',
       'Vendor24', 'AppB24', '3.5',
       'Vendor24', 'AppB24', '3.5',
       'vendor24', 'appb24',
       124, 1029,
       'UNKNOWN', FALSE);

INSERT INTO vulnerability_criteria_nodes (
    id, vulnerability_id, parent_id, root_group_no,
    node_type, operator, negate, sort_order
) VALUES
      (5051, 2024, NULL, 0, 'OPERATOR', 'AND', FALSE, 0),
      (5052, 2024, 5051, 0, 'LEAF_GROUP', NULL, FALSE, 0),
      (5053, 2024, 5051, 0, 'LEAF_GROUP', NULL, FALSE, 1);

INSERT INTO vulnerability_criteria_cpes (
    id, node_id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    match_vulnerable, dedupe_key
) VALUES
      (6051, 5052, 2024, 'cpe:2.3:a:vendor24:appa24:*:*:*:*:*:*:*:*',
       124, 1028,
       'vendor24', 'appa24',
       'a', '*', '*',
       '3.0', '', '4.0', '',
       TRUE, 'case24-crit-a'),
      (6052, 5053, 2024, 'cpe:2.3:a:vendor24:appb24:*:*:*:*:*:*:*:*',
       124, 1029,
       'vendor24', 'appb24',
       'a', '*', '*',
       '3.0', '', '4.0', '',
       TRUE, 'case24-crit-b');

INSERT INTO vulnerability_affected_cpes (
    id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    criteria_node_id, root_group_no, dedupe_key
) VALUES
      (40241, 2024, 'cpe:2.3:a:vendor24:appa24:*:*:*:*:*:*:*:*',
       124, 1028,
       'vendor24', 'appa24',
       'a', '*', '*',
       '3.0', '', '4.0', '',
       5052, 0, 'case24-flat-a'),
      (40242, 2024, 'cpe:2.3:a:vendor24:appb24:*:*:*:*:*:*:*:*',
       124, 1029,
       'vendor24', 'appb24',
       'a', '*', '*',
       '3.0', '', '4.0', '',
       5053, 0, 'case24-flat-b');