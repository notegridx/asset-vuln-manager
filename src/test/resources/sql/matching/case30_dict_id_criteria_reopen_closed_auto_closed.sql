UPDATE assets
SET platform = 'windows',
    os_name = 'Windows 11'
WHERE id = 1;

INSERT INTO cpe_vendors (
    id, name_norm, display_name, source
) VALUES
    (130, 'vendor30', 'Vendor30', 'TEST');

INSERT INTO cpe_products (
    id, vendor_id, name_norm, display_name, source
) VALUES
      (1042, 130, 'appa30', 'AppA30', 'TEST'),
      (1043, 130, 'appb30', 'AppB30', 'TEST');

INSERT INTO vulnerabilities (
    id, source, external_id, title, description,
    severity, cvss_version, cvss_score
) VALUES
    (2030, 'NVD', 'CVE-2099-0030', 'CASE-30', 'A AND B reopen', 'HIGH', '3.1', 8.9);

INSERT INTO software_installs (
    id, asset_id, type, source,
    vendor_raw, product_raw, version_raw,
    vendor, product, version,
    normalized_vendor, normalized_product,
    cpe_vendor_id, cpe_product_id,
    source_type, canonical_link_disabled
) VALUES
      (3033, 1, 'APPLICATION', 'MANUAL',
       'Vendor30', 'AppA30', '10.2',
       'Vendor30', 'AppA30', '10.2',
       'vendor30', 'appa30',
       130, 1042,
       'UNKNOWN', FALSE),
      (3034, 1, 'APPLICATION', 'MANUAL',
       'Vendor30', 'AppB30', '10.2',
       'Vendor30', 'AppB30', '10.2',
       'vendor30', 'appb30',
       130, 1043,
       'UNKNOWN', FALSE);

INSERT INTO vulnerability_criteria_nodes (
    id, vulnerability_id, parent_id, root_group_no,
    node_type, operator, negate, sort_order
) VALUES
      (5111, 2030, NULL, 0, 'OPERATOR', 'AND', FALSE, 0),
      (5112, 2030, 5111, 0, 'LEAF_GROUP', NULL, FALSE, 0),
      (5113, 2030, 5111, 0, 'LEAF_GROUP', NULL, FALSE, 1);

INSERT INTO vulnerability_criteria_cpes (
    id, node_id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    match_vulnerable, dedupe_key
) VALUES
      (6111, 5112, 2030, 'cpe:2.3:a:vendor30:appa30:*:*:*:*:*:*:*:*',
       130, 1042,
       'vendor30', 'appa30',
       'a', '*', '*',
       '10.0', '', '11.0', '',
       TRUE, 'case30-crit-a'),
      (6112, 5113, 2030, 'cpe:2.3:a:vendor30:appb30:*:*:*:*:*:*:*:*',
       130, 1043,
       'vendor30', 'appb30',
       'a', '*', '*',
       '10.0', '', '11.0', '',
       TRUE, 'case30-crit-b');

INSERT INTO vulnerability_affected_cpes (
    id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    criteria_node_id, root_group_no, dedupe_key
) VALUES
      (40301, 2030, 'cpe:2.3:a:vendor30:appa30:*:*:*:*:*:*:*:*',
       130, 1042,
       'vendor30', 'appa30',
       'a', '*', '*',
       '10.0', '', '11.0', '',
       5112, 0, 'case30-flat-a'),
      (40302, 2030, 'cpe:2.3:a:vendor30:appb30:*:*:*:*:*:*:*:*',
       130, 1043,
       'vendor30', 'appb30',
       'a', '*', '*',
       '10.0', '', '11.0', '',
       5113, 0, 'case30-flat-b');

INSERT INTO alerts (
    id, software_install_id, vulnerability_id,
    status, certainty, matched_by, close_reason,
    first_seen_at, last_seen_at, closed_at,
    created_at, updated_at
) VALUES
    (7030, 3033, 2030,
     'CLOSED', 'CONFIRMED', 'DICT_ID', 'AUTO_CLOSED_NO_LONGER_AFFECTED',
     CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6),
     CURRENT_TIMESTAMP(6), CURRENT_TIMESTAMP(6));