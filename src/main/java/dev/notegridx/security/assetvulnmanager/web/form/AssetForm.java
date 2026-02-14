package dev.notegridx.security.assetvulnmanager.web.form;

import jakarta.validation.constraints.NotBlank;

public class AssetForm {

	private String externalKey;
	
	@NotBlank(message = "Name is required")
	private String name;
	
	private String assetType;
	private String owner;
	private String note;

	public String getExternalKey() { return externalKey; }
	public void setExternalKey(String externalKey) { this.externalKey = externalKey; }
	
	public String getName() { return name; }
	public void setName(String name ) {this.name = name; }
	
	public String getAssetType() { return assetType; }
	public void setAssetType(String assetType) { this.assetType = assetType; }
	
	public String getOwner() { return owner; }
	public void setOwner(String owner) { this.owner = owner; }
	
	public String getNote() { return note; }
	public void setNote(String note) { this.note = note; }

}
