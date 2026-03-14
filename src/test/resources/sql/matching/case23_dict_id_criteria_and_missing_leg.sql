UPDATE assets
SET platform = 'windows',
    os_name = 'Windows 11'
WHERE id = 1;

INSERT INTO cpe_vendors (
    id, name_norm, display_name, source
) VALUES
    (123, 'vendor23', 'Vendor23', 'TEST');

INSERT INTO cpe_products (
    id, vendor_id, name_norm, display_name, source
) VALUES
      (1026, 123, 'appa23', 'AppA23', 'TEST'),
      (1027, 123, 'appb23', 'AppB23', 'TEST');

INSERT INTO vulnerabilities (
    id, source, external_id, title, description,
    severity, cvss_version, cvss_score
) VALUES
    (2023, 'NVD', 'CVE-2099-0023', 'CASE-23', 'A AND B, only A installed', 'HIGH', '3.1', 8.4);

INSERT INTO software_installs (
    id, asset_id, type, source,
    vendor_raw, product_raw, version_raw,
    vendor, product, version,
    normalized_vendor, normalized_product,
    cpe_vendor_id, cpe_product_id,
    source_type, canonical_link_disabled
) VALUES
    (3023, 1, 'APPLICATION', 'MANUAL',
     'Vendor23', 'AppA23', '3.0',
     'Vendor23', 'AppA23', '3.0',
     'vendor23', 'appa23',
     123, 1026,
     'UNKNOWN', FALSE);

INSERT INTO vulnerability_criteria_nodes (
    id, vulnerability_id, parent_id, root_group_no,
    node_type, operator, negate, sort_order
) VALUES
      (5041, 2023, NULL, 0, 'OPERATOR', 'AND', FALSE, 0),
      (5042, 2023, 5041, 0, 'LEAF_GROUP', NULL, FALSE, 0),
      (5043, 2023, 5041, 0, 'LEAF_GROUP', NULL, FALSE, 1);

INSERT INTO vulnerability_criteria_cpes (
    id, node_id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    match_vulnerable, dedupe_key
) VALUES
      (6041, 5042, 2023, 'cpe:2.3:a:vendor23:appa23:*:*:*:*:*:*:*:*',
       123, 1026,
       'vendor23', 'appa23',
       'a', '*', '*',
       '2.0', '', '4.0', '',
       TRUE, 'case23-crit-a'),
      (6042, 5043, 2023, 'cpe:2.3:a:vendor23:appb23:*:*:*:*:*:*:*:*',
       123, 1027,
       'vendor23', 'appb23',
       'a', '*', '*',
       '2.0', '', '4.0', '',
       TRUE, 'case23-crit-b');

INSERT INTO vulnerability_affected_cpes (
    id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    criteria_node_id, root_group_no, dedupe_key
) VALUES
      (40231, 2023, 'cpe:2.3:a:vendor23:appa23:*:*:*:*:*:*:*:*',
       123, 1026,
       'vendor23', 'appa23',
       'a', '*', '*',
       '2.0', '', '4.0', '',
       5042, 0, 'case23-flat-a'),
      (40232, 2023, 'cpe:2.3:a:vendor23:appb23:*:*:*:*:*:*:*:*',
       123, 1027,
       'vendor23', 'appb23',
       'a', '*', '*',
       '2.0', '', '4.0', '',
       5043, 0, 'case23-flat-b');