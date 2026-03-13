SET FOREIGN_KEY_CHECKS = 0;

DELETE FROM alerts;
DELETE FROM vulnerability_affected_cpes;
DELETE FROM software_installs;
DELETE FROM vulnerabilities;
DELETE FROM cpe_products;
DELETE FROM cpe_vendors;
DELETE FROM assets;

SET FOREIGN_KEY_CHECKS = 1;