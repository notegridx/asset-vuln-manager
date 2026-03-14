UPDATE assets
SET platform = 'windows',
    os_name = 'Windows 11'
WHERE id = 1;

INSERT INTO cpe_vendors (
    id, name_norm, display_name, source
) VALUES
    (125, 'vendor25', 'Vendor25', 'TEST');

INSERT INTO cpe_products (
    id, vendor_id, name_norm, display_name, source
) VALUES
      (1030, 125, 'appa25', 'AppA25', 'TEST'),
      (1031, 125, 'appb25', 'AppB25', 'TEST'),
      (1032, 125, 'appc25', 'AppC25', 'TEST');

INSERT INTO vulnerabilities (
    id, source, external_id, title, description,
    severity, cvss_version, cvss_score
) VALUES
    (2025, 'NVD', 'CVE-2099-0025', 'CASE-25', '(A OR B) AND C', 'HIGH', '3.1', 8.7);

INSERT INTO software_installs (
    id, asset_id, type, source,
    vendor_raw, product_raw, version_raw,
    vendor, product, version,
    normalized_vendor, normalized_product,
    cpe_vendor_id, cpe_product_id,
    source_type, canonical_link_disabled
) VALUES
      (3026, 1, 'APPLICATION', 'MANUAL',
       'Vendor25', 'AppB25', '5.1',
       'Vendor25', 'AppB25', '5.1',
       'vendor25', 'appb25',
       125, 1031,
       'UNKNOWN', FALSE),
      (3027, 1, 'APPLICATION', 'MANUAL',
       'Vendor25', 'AppC25', '5.1',
       'Vendor25', 'AppC25', '5.1',
       'vendor25', 'appc25',
       125, 1032,
       'UNKNOWN', FALSE);

INSERT INTO vulnerability_criteria_nodes (
    id, vulnerability_id, parent_id, root_group_no,
    node_type, operator, negate, sort_order
) VALUES
      (5061, 2025, NULL, 0, 'OPERATOR', 'AND', FALSE, 0),
      (5062, 2025, 5061, 0, 'LEAF_GROUP', NULL, FALSE, 0),
      (5063, 2025, 5061, 0, 'LEAF_GROUP', NULL, FALSE, 1);

INSERT INTO vulnerability_criteria_cpes (
    id, node_id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    match_vulnerable, dedupe_key
) VALUES
      (6061, 5062, 2025, 'cpe:2.3:a:vendor25:appa25:*:*:*:*:*:*:*:*',
       125, 1030,
       'vendor25', 'appa25',
       'a', '*', '*',
       '5.0', '', '6.0', '',
       TRUE, 'case25-crit-a'),
      (6062, 5062, 2025, 'cpe:2.3:a:vendor25:appb25:*:*:*:*:*:*:*:*',
       125, 1031,
       'vendor25', 'appb25',
       'a', '*', '*',
       '5.0', '', '6.0', '',
       TRUE, 'case25-crit-b'),
      (6063, 5063, 2025, 'cpe:2.3:a:vendor25:appc25:*:*:*:*:*:*:*:*',
       125, 1032,
       'vendor25', 'appc25',
       'a', '*', '*',
       '5.0', '', '6.0', '',
       TRUE, 'case25-crit-c');

INSERT INTO vulnerability_affected_cpes (
    id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    criteria_node_id, root_group_no, dedupe_key
) VALUES
      (40251, 2025, 'cpe:2.3:a:vendor25:appa25:*:*:*:*:*:*:*:*',
       125, 1030,
       'vendor25', 'appa25',
       'a', '*', '*',
       '5.0', '', '6.0', '',
       5062, 0, 'case25-flat-a'),
      (40252, 2025, 'cpe:2.3:a:vendor25:appb25:*:*:*:*:*:*:*:*',
       125, 1031,
       'vendor25', 'appb25',
       'a', '*', '*',
       '5.0', '', '6.0', '',
       5062, 0, 'case25-flat-b'),
      (40253, 2025, 'cpe:2.3:a:vendor25:appc25:*:*:*:*:*:*:*:*',
       125, 1032,
       'vendor25', 'appc25',
       'a', '*', '*',
       '5.0', '', '6.0', '',
       5063, 0, 'case25-flat-c');