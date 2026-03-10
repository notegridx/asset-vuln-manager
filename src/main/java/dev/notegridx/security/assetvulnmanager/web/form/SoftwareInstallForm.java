package dev.notegridx.security.assetvulnmanager.web.form;

import jakarta.validation.constraints.NotBlank;

public class SoftwareInstallForm {

	private String type;

	private String source;

	private String sourceType;

	private String vendor;

	@NotBlank(message = "Product is required")
	private String product;

	private String version;

	private String cpeName;

	private String vendorRaw;

	private String productRaw;

	private String versionRaw;

	private String lastSeenAt;

	private String installedAt;

	private String installLocation;

	private String packageIdentifier;

	private String arch;

	private String publisher;

	private String bundleId;

	private String packageManager;

	private String installSource;

	private String edition;

	private String channel;

	private String release;

	private String purl;

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}


	public String getSource() {
		return source;
	}

	public void setSource(String source) {
		this.source = source;
	}


	public String getSourceType() {
		return sourceType;
	}

	public void setSourceType(String sourceType) {
		this.sourceType = sourceType;
	}


	public String getVendor() {
		return vendor;
	}

	public void setVendor(String vendor) {
		this.vendor = vendor;
	}


	public String getProduct() {
		return product;
	}

	public void setProduct(String product) {
		this.product = product;
	}


	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}


	public String getCpeName() {
		return cpeName;
	}

	public void setCpeName(String cpeName) {
		this.cpeName = cpeName;
	}


	public String getVendorRaw() {
		return vendorRaw;
	}

	public void setVendorRaw(String vendorRaw) {
		this.vendorRaw = vendorRaw;
	}


	public String getProductRaw() {
		return productRaw;
	}

	public void setProductRaw(String productRaw) {
		this.productRaw = productRaw;
	}


	public String getVersionRaw() {
		return versionRaw;
	}

	public void setVersionRaw(String versionRaw) {
		this.versionRaw = versionRaw;
	}


	public String getLastSeenAt() {
		return lastSeenAt;
	}

	public void setLastSeenAt(String lastSeenAt) {
		this.lastSeenAt = lastSeenAt;
	}


	public String getInstalledAt() {
		return installedAt;
	}

	public void setInstalledAt(String installedAt) {
		this.installedAt = installedAt;
	}


	public String getInstallLocation() {
		return installLocation;
	}

	public void setInstallLocation(String installLocation) {
		this.installLocation = installLocation;
	}


	public String getPackageIdentifier() {
		return packageIdentifier;
	}

	public void setPackageIdentifier(String packageIdentifier) {
		this.packageIdentifier = packageIdentifier;
	}


	public String getArch() {
		return arch;
	}

	public void setArch(String arch) {
		this.arch = arch;
	}


	public String getPublisher() {
		return publisher;
	}

	public void setPublisher(String publisher) {
		this.publisher = publisher;
	}


	public String getBundleId() {
		return bundleId;
	}

	public void setBundleId(String bundleId) {
		this.bundleId = bundleId;
	}


	public String getPackageManager() {
		return packageManager;
	}

	public void setPackageManager(String packageManager) {
		this.packageManager = packageManager;
	}


	public String getInstallSource() {
		return installSource;
	}

	public void setInstallSource(String installSource) {
		this.installSource = installSource;
	}


	public String getEdition() {
		return edition;
	}

	public void setEdition(String edition) {
		this.edition = edition;
	}


	public String getChannel() {
		return channel;
	}

	public void setChannel(String channel) {
		this.channel = channel;
	}


	public String getRelease() {
		return release;
	}

	public void setRelease(String release) {
		this.release = release;
	}


	public String getPurl() {
		return purl;
	}

	public void setPurl(String purl) {
		this.purl = purl;
	}
}