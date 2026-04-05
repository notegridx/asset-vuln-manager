-- case35_dict_id_criteria_and_negate_block.sql
-- Expectation after negate fix:
--   A AND NOT(B)
--   Asset has A and B -> NO MATCH

-- Asset
INSERT INTO assets (
    id, external_key, name, asset_type, owner, note,
    source, platform, os_version,
    created_at, updated_at
) VALUES (
             3501, 'asset-3501', 'Host-Negate-Block-01', 'WORKSTATION', NULL, NULL,
             'MANUAL', 'windows', '11',
             NOW(), NOW()
         );

-- Canonical vendor/product required by FK from software_installs
INSERT INTO cpe_vendors (
    id, name_norm, display_name, source, created_at, updated_at
) VALUES (
             35001, 'vendor_negate', 'vendor_negate', 'CPE_DICT', NOW(), NOW()
         );

INSERT INTO cpe_products (
    id, vendor_id, name_norm, display_name, source, created_at, updated_at
) VALUES
      (
          35011, 35001, 'app_anchor', 'app_anchor', 'CPE_DICT', NOW(), NOW()
      ),
      (
          35012, 35001, 'app_exclude', 'app_exclude', 'CPE_DICT', NOW(), NOW()
      );

-- Software A (positive anchor)
INSERT INTO software_installs (
    id, asset_id, type, source,
    vendor_raw, product_raw, version_raw, version_norm, last_seen_at,
    vendor, product, version, cpe_name,
    normalized_vendor, normalized_product,
    cpe_vendor_id, cpe_product_id,
    canonical_link_disabled,
    source_type,
    created_at, updated_at
) VALUES (
             3511, 3501, 'APPLICATION', 'MANUAL',
             'vendor_negate', 'app_anchor', '1.5', '1.5', NOW(),
             'vendor_negate', 'app_anchor', '1.5', NULL,
             'vendor_negate', 'app_anchor',
             35001, 35011,
             FALSE,
             'UNKNOWN',
             NOW(), NOW()
         );

-- Software B (excluded app exists on same asset)
INSERT INTO software_installs (
    id, asset_id, type, source,
    vendor_raw, product_raw, version_raw, version_norm, last_seen_at,
    vendor, product, version, cpe_name,
    normalized_vendor, normalized_product,
    cpe_vendor_id, cpe_product_id,
    canonical_link_disabled,
    source_type,
    created_at, updated_at
) VALUES (
             3512, 3501, 'APPLICATION', 'MANUAL',
             'vendor_negate', 'app_exclude', '1.5', '1.5', NOW(),
             'vendor_negate', 'app_exclude', '1.5', NULL,
             'vendor_negate', 'app_exclude',
             35001, 35012,
             FALSE,
             'UNKNOWN',
             NOW(), NOW()
         );

-- Vulnerability
INSERT INTO vulnerabilities (
    id, source, external_id, description, severity,
    cvss_version, cvss_score,
    published_at, last_modified_at,
    kev_flag,
    created_at, updated_at
) VALUES (
             3591, 'NVD', 'CVE-2099-3501', 'A AND NOT(B) should be blocked when B exists', 'HIGH',
             '3.1', 7.5,
             NOW(), NOW(),
             FALSE,
             NOW(), NOW()
         );

-- Candidate row used by MatchingService preloading (positive anchor only)
INSERT INTO vulnerability_affected_cpes (
    id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    criteria_node_id, root_group_no, dedupe_key,
    created_at, updated_at
) VALUES (
             3521, 3591, 'cpe:2.3:a:vendor_negate:app_anchor:*:*:*:*:*:*:*:*',
             35001, 35011,
             'vendor_negate', 'app_anchor',
             'a', '*', '*',
             '1.0', '', '2.0', '',
             3531, 0, 'case35-anchor',
             NOW(), NOW()
         );

-- Criteria tree root: AND
INSERT INTO vulnerability_criteria_nodes (
    id, vulnerability_id, parent_id, root_group_no,
    node_type, operator, negate, sort_order,
    created_at, updated_at
) VALUES (
             3530, 3591, NULL, 0,
             'OPERATOR', 'AND', FALSE, 0,
             NOW(), NOW()
         );

-- Leaf A: positive
INSERT INTO vulnerability_criteria_nodes (
    id, vulnerability_id, parent_id, root_group_no,
    node_type, operator, negate, sort_order,
    created_at, updated_at
) VALUES (
             3531, 3591, 3530, 0,
             'LEAF_GROUP', 'OR', FALSE, 0,
             NOW(), NOW()
         );

INSERT INTO vulnerability_criteria_cpes (
    id, node_id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    match_vulnerable, dedupe_key,
    created_at, updated_at
) VALUES (
             3541, 3531, 3591, 'cpe:2.3:a:vendor_negate:app_anchor:*:*:*:*:*:*:*:*',
             35001, 35011,
             'vendor_negate', 'app_anchor',
             'a', '*', '*',
             '1.0', '', '2.0', '',
             TRUE, 'case35-leaf-a',
             NOW(), NOW()
         );

-- Leaf B: negated exclusion
INSERT INTO vulnerability_criteria_nodes (
    id, vulnerability_id, parent_id, root_group_no,
    node_type, operator, negate, sort_order,
    created_at, updated_at
) VALUES (
             3532, 3591, 3530, 0,
             'LEAF_GROUP', 'OR', TRUE, 1,
             NOW(), NOW()
         );

INSERT INTO vulnerability_criteria_cpes (
    id, node_id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    match_vulnerable, dedupe_key,
    created_at, updated_at
) VALUES (
             3542, 3532, 3591, 'cpe:2.3:a:vendor_negate:app_exclude:*:*:*:*:*:*:*:*',
             35001, 35012,
             'vendor_negate', 'app_exclude',
             'a', '*', '*',
             '1.0', '', '2.0', '',
             TRUE, 'case35-leaf-b',
             NOW(), NOW()
         );