UPDATE assets
SET platform = 'windows',
    os_name = 'Windows 11'
WHERE id = 1;

INSERT INTO cpe_vendors (
    id, name_norm, display_name, source
) VALUES
    (127, 'vendor27', 'Vendor27', 'TEST');

INSERT INTO cpe_products (
    id, vendor_id, name_norm, display_name, source
) VALUES
      (1036, 127, 'appa27', 'AppA27', 'TEST'),
      (1037, 127, 'appc27', 'AppC27', 'TEST');

INSERT INTO vulnerabilities (
    id, source, external_id, description,
    severity, cvss_version, cvss_score
) VALUES
    (2027, 'NVD', 'CVE-2099-0027',  'A(version) AND C', 'HIGH', '3.1', 8.5);

INSERT INTO software_installs (
    id, asset_id, type, source,
    vendor_raw, product_raw, version_raw,
    vendor, product, version,
    normalized_vendor, normalized_product,
    cpe_vendor_id, cpe_product_id,
    source_type, canonical_link_disabled
) VALUES
      (3029, 1, 'APPLICATION', 'MANUAL',
       'Vendor27', 'AppA27', NULL,
       'Vendor27', 'AppA27', '',
       'vendor27', 'appa27',
       127, 1036,
       'UNKNOWN', FALSE),
      (3030, 1, 'APPLICATION', 'MANUAL',
       'Vendor27', 'AppC27', '7.1',
       'Vendor27', 'AppC27', '7.1',
       'vendor27', 'appc27',
       127, 1037,
       'UNKNOWN', FALSE);

INSERT INTO vulnerability_criteria_nodes (
    id, vulnerability_id, parent_id, root_group_no,
    node_type, operator, negate, sort_order
) VALUES
      (5081, 2027, NULL, 0, 'OPERATOR', 'AND', FALSE, 0),
      (5082, 2027, 5081, 0, 'LEAF_GROUP', NULL, FALSE, 0),
      (5083, 2027, 5081, 0, 'LEAF_GROUP', NULL, FALSE, 1);

INSERT INTO vulnerability_criteria_cpes (
    id, node_id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    match_vulnerable, dedupe_key
) VALUES
      (6081, 5082, 2027, 'cpe:2.3:a:vendor27:appa27:*:*:*:*:*:*:*:*',
       127, 1036,
       'vendor27', 'appa27',
       'a', '*', '*',
       '7.0', '', '8.0', '',
       TRUE, 'case27-crit-a'),
      (6082, 5083, 2027, 'cpe:2.3:a:vendor27:appc27:*:*:*:*:*:*:*:*',
       127, 1037,
       'vendor27', 'appc27',
       'a', '*', '*',
       '7.0', '', '8.0', '',
       TRUE, 'case27-crit-c');

INSERT INTO vulnerability_affected_cpes (
    id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    criteria_node_id, root_group_no, dedupe_key
) VALUES
      (40271, 2027, 'cpe:2.3:a:vendor27:appa27:*:*:*:*:*:*:*:*',
       127, 1036,
       'vendor27', 'appa27',
       'a', '*', '*',
       '7.0', '', '8.0', '',
       5082, 0, 'case27-flat-a'),
      (40272, 2027, 'cpe:2.3:a:vendor27:appc27:*:*:*:*:*:*:*:*',
       127, 1037,
       'vendor27', 'appc27',
       'a', '*', '*',
       '7.0', '', '8.0', '',
       5083, 0, 'case27-flat-c');