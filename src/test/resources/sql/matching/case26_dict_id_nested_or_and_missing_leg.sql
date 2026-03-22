UPDATE assets
SET platform = 'windows',
    os_name = 'Windows 11'
WHERE id = 1;

INSERT INTO cpe_vendors (
    id, name_norm, display_name, source
) VALUES
    (126, 'vendor26', 'Vendor26', 'TEST');

INSERT INTO cpe_products (
    id, vendor_id, name_norm, display_name, source
) VALUES
      (1033, 126, 'appa26', 'AppA26', 'TEST'),
      (1034, 126, 'appb26', 'AppB26', 'TEST'),
      (1035, 126, 'appc26', 'AppC26', 'TEST');

INSERT INTO vulnerabilities (
    id, source, external_id, description,
    severity, cvss_version, cvss_score
) VALUES
    (2026, 'NVD', 'CVE-2099-0026',  '(A OR B) AND C, C missing', 'HIGH', '3.1', 8.2);

INSERT INTO software_installs (
    id, asset_id, type, source,
    vendor_raw, product_raw, version_raw,
    vendor, product, version,
    normalized_vendor, normalized_product,
    cpe_vendor_id, cpe_product_id,
    source_type, canonical_link_disabled
) VALUES
    (3028, 1, 'APPLICATION', 'MANUAL',
     'Vendor26', 'AppB26', '5.1',
     'Vendor26', 'AppB26', '5.1',
     'vendor26', 'appb26',
     126, 1034,
     'UNKNOWN', FALSE);

INSERT INTO vulnerability_criteria_nodes (
    id, vulnerability_id, parent_id, root_group_no,
    node_type, operator, negate, sort_order
) VALUES
      (5071, 2026, NULL, 0, 'OPERATOR', 'AND', FALSE, 0),
      (5072, 2026, 5071, 0, 'LEAF_GROUP', NULL, FALSE, 0),
      (5073, 2026, 5071, 0, 'LEAF_GROUP', NULL, FALSE, 1);

INSERT INTO vulnerability_criteria_cpes (
    id, node_id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    match_vulnerable, dedupe_key
) VALUES
      (6071, 5072, 2026, 'cpe:2.3:a:vendor26:appa26:*:*:*:*:*:*:*:*',
       126, 1033,
       'vendor26', 'appa26',
       'a', '*', '*',
       '5.0', '', '6.0', '',
       TRUE, 'case26-crit-a'),
      (6072, 5072, 2026, 'cpe:2.3:a:vendor26:appb26:*:*:*:*:*:*:*:*',
       126, 1034,
       'vendor26', 'appb26',
       'a', '*', '*',
       '5.0', '', '6.0', '',
       TRUE, 'case26-crit-b'),
      (6073, 5073, 2026, 'cpe:2.3:a:vendor26:appc26:*:*:*:*:*:*:*:*',
       126, 1035,
       'vendor26', 'appc26',
       'a', '*', '*',
       '5.0', '', '6.0', '',
       TRUE, 'case26-crit-c');

INSERT INTO vulnerability_affected_cpes (
    id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    criteria_node_id, root_group_no, dedupe_key
) VALUES
      (40261, 2026, 'cpe:2.3:a:vendor26:appa26:*:*:*:*:*:*:*:*',
       126, 1033,
       'vendor26', 'appa26',
       'a', '*', '*',
       '5.0', '', '6.0', '',
       5072, 0, 'case26-flat-a'),
      (40262, 2026, 'cpe:2.3:a:vendor26:appb26:*:*:*:*:*:*:*:*',
       126, 1034,
       'vendor26', 'appb26',
       'a', '*', '*',
       '5.0', '', '6.0', '',
       5072, 0, 'case26-flat-b'),
      (40263, 2026, 'cpe:2.3:a:vendor26:appc26:*:*:*:*:*:*:*:*',
       126, 1035,
       'vendor26', 'appc26',
       'a', '*', '*',
       '5.0', '', '6.0', '',
       5073, 0, 'case26-flat-c');