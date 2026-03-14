UPDATE assets
SET platform = 'windows',
    os_name = 'Windows 11'
WHERE id = 1;

INSERT INTO cpe_vendors (
    id, name_norm, display_name, source
) VALUES
    (121, 'vendor21', 'Vendor21', 'TEST');

INSERT INTO cpe_products (
    id, vendor_id, name_norm, display_name, source
) VALUES
      (1021, 121, 'appa21', 'AppA21', 'TEST'),
      (1022, 121, 'appb21', 'AppB21', 'TEST');

INSERT INTO vulnerabilities (
    id, source, external_id, title, description,
    severity, cvss_version, cvss_score
) VALUES
    (2021, 'NVD', 'CVE-2099-0021', 'CASE-21', 'A OR B', 'HIGH', '3.1', 8.0);

INSERT INTO software_installs (
    id, asset_id, type, source,
    vendor_raw, product_raw, version_raw,
    vendor, product, version,
    normalized_vendor, normalized_product,
    cpe_vendor_id, cpe_product_id,
    source_type, canonical_link_disabled
) VALUES
    (3021, 1, 'APPLICATION', 'MANUAL',
     'Vendor21', 'AppA21', '1.5',
     'Vendor21', 'AppA21', '1.5',
     'vendor21', 'appa21',
     121, 1021,
     'UNKNOWN', FALSE);

INSERT INTO vulnerability_criteria_nodes (
    id, vulnerability_id, parent_id, root_group_no,
    node_type, operator, negate, sort_order
) VALUES
      (5021, 2021, NULL, 0, 'OPERATOR', 'OR', FALSE, 0),
      (5022, 2021, 5021, 0, 'LEAF_GROUP', NULL, FALSE, 0);

INSERT INTO vulnerability_criteria_cpes (
    id, node_id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    match_vulnerable, dedupe_key
) VALUES
      (6021, 5022, 2021, 'cpe:2.3:a:vendor21:appa21:*:*:*:*:*:*:*:*',
       121, 1021,
       'vendor21', 'appa21',
       'a', '*', '*',
       '1.0', '', '2.0', '',
       TRUE, 'case21-crit-a'),
      (6022, 5022, 2021, 'cpe:2.3:a:vendor21:appb21:*:*:*:*:*:*:*:*',
       121, 1022,
       'vendor21', 'appb21',
       'a', '*', '*',
       '1.0', '', '2.0', '',
       TRUE, 'case21-crit-b');

INSERT INTO vulnerability_affected_cpes (
    id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    criteria_node_id, root_group_no, dedupe_key
) VALUES
      (40211, 2021, 'cpe:2.3:a:vendor21:appa21:*:*:*:*:*:*:*:*',
       121, 1021,
       'vendor21', 'appa21',
       'a', '*', '*',
       '1.0', '', '2.0', '',
       5022, 0, 'case21-flat-a'),
      (40212, 2021, 'cpe:2.3:a:vendor21:appb21:*:*:*:*:*:*:*:*',
       121, 1022,
       'vendor21', 'appb21',
       'a', '*', '*',
       '1.0', '', '2.0', '',
       5022, 0, 'case21-flat-b');