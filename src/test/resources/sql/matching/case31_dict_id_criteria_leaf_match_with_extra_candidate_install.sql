UPDATE assets
SET platform = 'windows',
    os_name = 'Windows 11'
WHERE id = 1;

INSERT INTO cpe_vendors (
    id, name_norm, display_name, source
) VALUES
    (131, 'vendor31', 'Vendor31', 'TEST');

INSERT INTO cpe_products (
    id, vendor_id, name_norm, display_name, source
) VALUES
      (1044, 131, 'appa31', 'AppA31', 'TEST'),
      (1045, 131, 'appb31', 'AppB31', 'TEST');

INSERT INTO vulnerabilities (
    id, source, external_id, description,
    severity, cvss_version, cvss_score
) VALUES
    (2031, 'NVD', 'CVE-2099-0031',  'criteria leaf picks only AppA31', 'HIGH', '3.1', 8.1);

INSERT INTO software_installs (
    id, asset_id, type, source,
    vendor_raw, product_raw, version_raw,
    vendor, product, version,
    normalized_vendor, normalized_product,
    cpe_vendor_id, cpe_product_id,
    source_type, canonical_link_disabled
) VALUES
      (3035, 1, 'APPLICATION', 'MANUAL',
       'Vendor31', 'AppA31', '10.5',
       'Vendor31', 'AppA31', '10.5',
       'vendor31', 'appa31',
       131, 1044,
       'UNKNOWN', FALSE),
      (3036, 1, 'APPLICATION', 'MANUAL',
       'Vendor31', 'AppB31', '10.5',
       'Vendor31', 'AppB31', '10.5',
       'vendor31', 'appb31',
       131, 1045,
       'UNKNOWN', FALSE);

INSERT INTO vulnerability_criteria_nodes (
    id, vulnerability_id, parent_id, root_group_no,
    node_type, operator, negate, sort_order
) VALUES
      (5121, 2031, NULL, 0, 'OPERATOR', 'OR', FALSE, 0),
      (5122, 2031, 5121, 0, 'LEAF_GROUP', NULL, FALSE, 0);

INSERT INTO vulnerability_criteria_cpes (
    id, node_id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    match_vulnerable, dedupe_key
) VALUES
    (6121, 5122, 2031, 'cpe:2.3:a:vendor31:appa31:*:*:*:*:*:*:*:*',
     131, 1044,
     'vendor31', 'appa31',
     'a', '*', '*',
     '10.0', '', '11.0', '',
     TRUE, 'case31-crit-a');

INSERT INTO vulnerability_affected_cpes (
    id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    criteria_node_id, root_group_no, dedupe_key
) VALUES
      (40311, 2031, 'cpe:2.3:a:vendor31:appa31:*:*:*:*:*:*:*:*',
       131, 1044,
       'vendor31', 'appa31',
       'a', '*', '*',
       '10.0', '', '11.0', '',
       5122, 0, 'case31-flat-a'),
      (40312, 2031, 'cpe:2.3:a:vendor31:appb31:*:*:*:*:*:*:*:*',
       131, 1045,
       'vendor31', 'appb31',
       'a', '*', '*',
       '10.0', '', '11.0', '',
       5122, 0, 'case31-flat-b');