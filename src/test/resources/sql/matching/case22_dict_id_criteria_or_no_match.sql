UPDATE assets
SET platform = 'windows',
    os_name = 'Windows 11'
WHERE id = 1;

INSERT INTO cpe_vendors (
    id, name_norm, display_name, source
) VALUES
    (122, 'vendor22', 'Vendor22', 'TEST');

INSERT INTO cpe_products (
    id, vendor_id, name_norm, display_name, source
) VALUES
      (1023, 122, 'appa22', 'AppA22', 'TEST'),
      (1024, 122, 'appb22', 'AppB22', 'TEST'),
      (1025, 122, 'appc22', 'AppC22', 'TEST');

INSERT INTO vulnerabilities (
    id, source, external_id, title, description,
    severity, cvss_version, cvss_score
) VALUES
    (2022, 'NVD', 'CVE-2099-0022', 'CASE-22', 'A OR B but C installed', 'MEDIUM', '3.1', 6.5);

INSERT INTO software_installs (
    id, asset_id, type, source,
    vendor_raw, product_raw, version_raw,
    vendor, product, version,
    normalized_vendor, normalized_product,
    cpe_vendor_id, cpe_product_id,
    source_type, canonical_link_disabled
) VALUES
    (3022, 1, 'APPLICATION', 'MANUAL',
     'Vendor22', 'AppC22', '1.5',
     'Vendor22', 'AppC22', '1.5',
     'vendor22', 'appc22',
     122, 1025,
     'UNKNOWN', FALSE);

INSERT INTO vulnerability_criteria_nodes (
    id, vulnerability_id, parent_id, root_group_no,
    node_type, operator, negate, sort_order
) VALUES
      (5031, 2022, NULL, 0, 'OPERATOR', 'OR', FALSE, 0),
      (5032, 2022, 5031, 0, 'LEAF_GROUP', NULL, FALSE, 0);

INSERT INTO vulnerability_criteria_cpes (
    id, node_id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    match_vulnerable, dedupe_key
) VALUES
      (6031, 5032, 2022, 'cpe:2.3:a:vendor22:appa22:*:*:*:*:*:*:*:*',
       122, 1023,
       'vendor22', 'appa22',
       'a', '*', '*',
       '1.0', '', '2.0', '',
       TRUE, 'case22-crit-a'),
      (6032, 5032, 2022, 'cpe:2.3:a:vendor22:appb22:*:*:*:*:*:*:*:*',
       122, 1024,
       'vendor22', 'appb22',
       'a', '*', '*',
       '1.0', '', '2.0', '',
       TRUE, 'case22-crit-b');

INSERT INTO vulnerability_affected_cpes (
    id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    criteria_node_id, root_group_no, dedupe_key
) VALUES
      (40221, 2022, 'cpe:2.3:a:vendor22:appa22:*:*:*:*:*:*:*:*',
       122, 1023,
       'vendor22', 'appa22',
       'a', '*', '*',
       '1.0', '', '2.0', '',
       5032, 0, 'case22-flat-a'),
      (40222, 2022, 'cpe:2.3:a:vendor22:appb22:*:*:*:*:*:*:*:*',
       122, 1024,
       'vendor22', 'appb22',
       'a', '*', '*',
       '1.0', '', '2.0', '',
       5032, 0, 'case22-flat-b');