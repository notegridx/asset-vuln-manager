-- case34_dict_id_criteria_and_negate_match.sql
-- Expectation after negate fix:
--   A AND NOT(B)
--   Asset has A only -> MATCH

-- Asset
INSERT INTO assets (
    id, external_key, name, asset_type, owner, note,
    source, platform, os_version,
    created_at, updated_at
) VALUES (
             3401, 'asset-3401', 'Host-Negate-Match-01', 'WORKSTATION', NULL, NULL,
             'MANUAL', 'windows', '11',
             NOW(), NOW()
         );

-- Canonical vendor/product required by FK from software_installs
INSERT INTO cpe_vendors (
    id, name_norm, display_name, source, created_at, updated_at
) VALUES (
             34001, 'vendor_negate', 'vendor_negate', 'CPE_DICT', NOW(), NOW()
         );

INSERT INTO cpe_products (
    id, vendor_id, name_norm, display_name, source, created_at, updated_at
) VALUES
      (
          34011, 34001, 'app_anchor', 'app_anchor', 'CPE_DICT', NOW(), NOW()
      ),
      (
          34012, 34001, 'app_exclude', 'app_exclude', 'CPE_DICT', NOW(), NOW()
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
             3411, 3401, 'APPLICATION', 'MANUAL',
             'vendor_negate', 'app_anchor', '1.5', '1.5', NOW(),
             'vendor_negate', 'app_anchor', '1.5', NULL,
             'vendor_negate', 'app_anchor',
             34001, 34011,
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
             3491, 'NVD', 'CVE-2099-3401', 'A AND NOT(B) should match when B is absent', 'HIGH',
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
             3421, 3491, 'cpe:2.3:a:vendor_negate:app_anchor:*:*:*:*:*:*:*:*',
             34001, 34011,
             'vendor_negate', 'app_anchor',
             'a', '*', '*',
             '1.0', '', '2.0', '',
             3431, 0, 'case34-anchor',
             NOW(), NOW()
         );

-- Criteria tree root: AND
INSERT INTO vulnerability_criteria_nodes (
    id, vulnerability_id, parent_id, root_group_no,
    node_type, operator, negate, sort_order,
    created_at, updated_at
) VALUES (
             3430, 3491, NULL, 0,
             'OPERATOR', 'AND', FALSE, 0,
             NOW(), NOW()
         );

-- Leaf A: positive
INSERT INTO vulnerability_criteria_nodes (
    id, vulnerability_id, parent_id, root_group_no,
    node_type, operator, negate, sort_order,
    created_at, updated_at
) VALUES (
             3431, 3491, 3430, 0,
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
             3441, 3431, 3491, 'cpe:2.3:a:vendor_negate:app_anchor:*:*:*:*:*:*:*:*',
             34001, 34011,
             'vendor_negate', 'app_anchor',
             'a', '*', '*',
             '1.0', '', '2.0', '',
             TRUE, 'case34-leaf-a',
             NOW(), NOW()
         );

-- Leaf B: negated exclusion
INSERT INTO vulnerability_criteria_nodes (
    id, vulnerability_id, parent_id, root_group_no,
    node_type, operator, negate, sort_order,
    created_at, updated_at
) VALUES (
             3432, 3491, 3430, 0,
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
             3442, 3432, 3491, 'cpe:2.3:a:vendor_negate:app_exclude:*:*:*:*:*:*:*:*',
             34001, 34012,
             'vendor_negate', 'app_exclude',
             'a', '*', '*',
             '1.0', '', '2.0', '',
             TRUE, 'case34-leaf-b',
             NOW(), NOW()
         );