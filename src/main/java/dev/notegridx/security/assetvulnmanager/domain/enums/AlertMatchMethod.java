package dev.notegridx.security.assetvulnmanager.domain.enums;

public enum AlertMatchMethod {
    DICT_ID,   // cpe_vendor_id + cpe_product_id
    NORM,      // vendor_norm + product_norm
    CPE_NAME   // cpe_name exact
}