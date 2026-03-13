INSERT INTO assets (
    id, external_key, name, asset_type, source
) VALUES
    (1, 'asset-case-host-01', 'Case Host 01', 'ENDPOINT', 'MANUAL');

INSERT INTO cpe_vendors (
    id, name_norm, display_name, source
) VALUES
      (101, 'acme', 'Acme', 'CPE_DICT'),
      (102, 'othercorp', 'OtherCorp', 'CPE_DICT');

INSERT INTO cpe_products (
    id, vendor_id, name_norm, display_name, source
) VALUES
      (1001, 101, 'widget', 'Acme Widget', 'CPE_DICT'),
      (1002, 101, 'otherwidget', 'Acme OtherWidget', 'CPE_DICT'),
      (1003, 102, 'widget', 'OtherCorp Widget', 'CPE_DICT');