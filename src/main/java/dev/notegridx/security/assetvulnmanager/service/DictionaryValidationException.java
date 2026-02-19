package dev.notegridx.security.assetvulnmanager.service;

public class DictionaryValidationException extends RuntimeException {

    private final DictionaryErrorCode code;
    private final String field;     // "vendor" or "product"
    private final String vendorNorm;
    private final String productNorm;

    public DictionaryValidationException(
            DictionaryErrorCode code,
            String field,
            String message,
            String vendorNorm,
            String productNorm
    ) {
        super(message);
        this.code = code;
        this.field = field;
        this.vendorNorm = vendorNorm;
        this.productNorm = productNorm;
    }

    public DictionaryErrorCode getCode() { return code; }
    public String getField() { return field; }
    public String getVendorNorm() { return vendorNorm; }
    public String getProductNorm() { return productNorm; }

    public enum DictionaryErrorCode {
        DICT_VENDOR_REQUIRED,
        DICT_VENDOR_NOT_FOUND,
        DICT_PRODUCT_REQUIRED,
        DICT_PRODUCT_NOT_FOUND
    }
}
