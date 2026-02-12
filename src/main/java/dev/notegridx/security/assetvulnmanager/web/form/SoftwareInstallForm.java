package dev.notegridx.security.assetvulnmanager.web.form;

import jakarta.validation.constraints.NotBlank;

public class SoftwareInstallForm {
	
	private String vendor;
	
	@NotBlank(message = "Product is required")
	private String product;
	
	private String version;
	
	private String cpeName;
	
	public String getVendor() { return vendor; }
	public void setVendor(String vendor) { this.vendor = vendor; }
	
	public String getProduct() { return product; }
	public void setProduct(String product) { this.product = product; }
	
	public String getVersion() { return version; }
	public void setVersion(String version) { this.version = version; }
	
	public String getCpeName() { return cpeName; }
	public void setCpeName(String cpeName) { this.cpeName = cpeName; }
	

}
