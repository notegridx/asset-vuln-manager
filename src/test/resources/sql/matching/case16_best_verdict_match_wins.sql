INSERT INTO vulnerabilities (
    id, source, external_id, title, description,
    severity, cvss_version, cvss_score
) VALUES
    (2016, 'NVD', 'CVE-2099-0016', 'CASE-16', 'best verdict MATCH wins', 'HIGH', '3.1', 8.4);

INSERT INTO software_installs (
    id, asset_id, type, source,
    vendor_raw, product_raw, version_raw,
    vendor, product, version,
    normalized_vendor, normalized_product,
    cpe_vendor_id, cpe_product_id,
    source_type, canonical_link_disabled
) VALUES
    (3016, 1, 'APPLICATION', 'MANUAL',
     'Acme', 'Widget BestVerdict', '15.0',
     'Acme', 'Widget BestVerdict', '15.0',
     'acme', 'widget',
     101, 1001,
     'UNKNOWN', FALSE);

INSERT INTO vulnerability_affected_cpes (
    id, vulnerability_id, cpe_name,
    cpe_vendor_id, cpe_product_id,
    vendor_norm, product_norm,
    version_start_including, version_start_excluding,
    version_end_including, version_end_excluding,
    dedupe_key
) VALUES
      (4016, 2016, 'cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*',
       101, 1001,
       'acme', 'widget',
       '1.0', '', '2.0', '',
       'case16a'),
      (4017, 2016, 'cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*',
       101, 1001,
       'acme', 'widget',
       '10.0', '', '20.0', '',
       'case16b');