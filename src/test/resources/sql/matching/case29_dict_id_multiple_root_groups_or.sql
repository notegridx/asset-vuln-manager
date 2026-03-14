UPDATE assets
SET platform = 'windows',
    os_name = 'Windows 11'
WHERE id = 1;

INSERT INTO cpe_vendors (
    id, name_norm, display_name, source
) VALUES
    (129, 'vendor29', 'Vendor29', 'TEST');

INSERT INTO cpe_products (
    id, vendor_id, name_norm, display_name, source
) VALUES
      (1039, 129, 'appa29', 'AppA29', 'TEST'),
      (1040, 129, 'appb29', 'AppB29', 'TEST'),
      (1041, 129, 'appd29', 'AppD29', 'TEST');

INSERT INTO vulnerabilities (
    id, source, external_id, title, description,
    severity, cvss_version, cvss_score
) VALUES
    (2029, 'NVD', 'CVE-2099-0029', 'CASE-29', '(A AND B) OR D', 'CRITICAL', '3.1', 9.4);

INSERT INTO software_installs (
    id, asset_id, type, source,
    vendor_raw, product_raw, version_raw,
    vendor, product, version,
    normalized_vendor, normalized_product,
    cpe_vendor_id, cpe_product_id,
    source_type, canonical_link_disabled
) VALUES
    (3032, 1, 'APPLICATION', 'MANUAL',
     'Vendor29', 'AppD29', '9.5',
     'Vendor29', 'AppD29', '9.5',
     'vendor29', 'appd29',
     129, 1041,
     'UNKNOWN', FALSE);

INSERT INTO vulnerability_criteria_nodes (
    id, vulnerability_id, parent_id, root_group_no,
    node_type, operator, negate, sort_order
) VALUES
      (5101, 2029, NULL, 0, 'OPERATOR', 'AND', FALSE, 0),
      (5102, 2029, 5101, 0, 'LEAF_GROUP', NULL, FALSE, 0),
      (5103, 2029, 5101, 0, 'LEAF_GROUP', NULL, FALSE, 1),
      (5104, 2029, NULL, 1, 'LEAF_GROUP', NULL, FALSE, 0);

INSERT INTO vulnerability_criteria_cpes (
    id, node_id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    match_vulnerable, dedupe_key
) VALUES
      (6101, 5102, 2029, 'cpe:2.3:a:vendor29:appa29:*:*:*:*:*:*:*:*',
       129, 1039,
       'vendor29', 'appa29',
       'a', '*', '*',
       '9.0', '', '10.0', '',
       TRUE, 'case29-crit-a'),
      (6102, 5103, 2029, 'cpe:2.3:a:vendor29:appb29:*:*:*:*:*:*:*:*',
       129, 1040,
       'vendor29', 'appb29',
       'a', '*', '*',
       '9.0', '', '10.0', '',
       TRUE, 'case29-crit-b'),
      (6103, 5104, 2029, 'cpe:2.3:a:vendor29:appd29:*:*:*:*:*:*:*:*',
       129, 1041,
       'vendor29', 'appd29',
       'a', '*', '*',
       '9.0', '', '10.0', '',
       TRUE, 'case29-crit-d');

INSERT INTO vulnerability_affected_cpes (
    id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    criteria_node_id, root_group_no, dedupe_key
) VALUES
      (40291, 2029, 'cpe:2.3:a:vendor29:appa29:*:*:*:*:*:*:*:*',
       129, 1039,
       'vendor29', 'appa29',
       'a', '*', '*',
       '9.0', '', '10.0', '',
       5102, 0, 'case29-flat-a'),
      (40292, 2029, 'cpe:2.3:a:vendor29:appb29:*:*:*:*:*:*:*:*',
       129, 1040,
       'vendor29', 'appb29',
       'a', '*', '*',
       '9.0', '', '10.0', '',
       5103, 0, 'case29-flat-b'),
      (40293, 2029, 'cpe:2.3:a:vendor29:appd29:*:*:*:*:*:*:*:*',
       129, 1041,
       'vendor29', 'appd29',
       'a', '*', '*',
       '9.0', '', '10.0', '',
       5104, 1, 'case29-flat-d');