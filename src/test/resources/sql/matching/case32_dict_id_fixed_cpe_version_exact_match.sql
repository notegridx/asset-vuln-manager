-- Fixed version in CPE name only (no explicit version range columns).
-- Should match when installed software version is exactly equal.

INSERT INTO cpe_vendors (id, name_norm, display_name, source, created_at, updated_at)
VALUES (91001, 'mozilla', 'Mozilla', 'CPE_DICT', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO cpe_products (id, vendor_id, name_norm, display_name, source, created_at, updated_at)
VALUES (92001, 91001, 'firefox', 'Firefox', 'CPE_DICT', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);

INSERT INTO assets (
    id, external_key, name, asset_type, owner, note,
    source, platform, os_version, created_at, updated_at, last_seen_at
) VALUES (
             93001, 'asset-fixed-version-match', 'Host-Fixed-Version-Match', 'WORKSTATION', null, null,
             'MANUAL', 'windows', '11', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
         );

INSERT INTO software_installs (
    id, asset_id, type, source,
    vendor_raw, product_raw, version_raw, version_norm, last_seen_at, import_run_id,
    install_location, installed_at, package_identifier, arch, source_type,
    publisher, bundle_id, package_manager, install_source, edition, channel, release_label, purl,
    vendor, product, version, cpe_name, normalized_vendor, normalized_product,
    created_at, updated_at, cpe_vendor_id, cpe_product_id, canonical_link_disabled
) VALUES (
             94001, 93001, 'APPLICATION', 'MANUAL',
             'Mozilla', 'Mozilla Firefox (x64 en-US)', '129.0', '129.0', CURRENT_TIMESTAMP, null,
             null, null, null, 'x64', 'UNKNOWN',
             null, null, null, null, null, null, null, null,
             'Mozilla', 'Mozilla Firefox (x64 en-US)', '129.0', null, 'mozilla', 'firefox',
             CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 91001, 92001, false
         );

INSERT INTO vulnerabilities (
    id, source, external_id, description, severity, cvss_version, cvss_score,
    published_at, last_modified_at, kev_flag, created_at, updated_at
) VALUES (
             95001, 'NVD', 'CVE-2099-9032',
             'Fixed-version CPE should match exactly equal software version',
             'HIGH', '3.1', 7.5,
             CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, false, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
         );

INSERT INTO vulnerability_affected_cpes (
    id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    cpe_part, target_sw, target_hw,
    version_start_including, version_start_excluding, version_end_including, version_end_excluding,
    criteria_node_id, root_group_no, dedupe_key, created_at, updated_at
) VALUES (
             96001, 95001, 'cpe:2.3:a:mozilla:firefox:129.0:*:*:*:*:*:*:*',
             91001, 92001,
             'mozilla', 'firefox',
             'a', '*', '*',
             '', '', '', '',
             null, 0, 'case32-fixed-version-exact-match', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
         );