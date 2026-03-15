package dev.notegridx.security.assetvulnmanager.web.form;

import jakarta.validation.constraints.NotBlank;

public class AssetForm {

    private String externalKey;

    @NotBlank(message = "Name is required")
    private String name;

    private String assetType;
    private String owner;
    private String note;

    private String source;
    private String platform;
    private String osVersion;

    private String systemUuid;
    private String serialNumber;
    private String hardwareVendor;
    private String hardwareModel;
    private String hardwareVersion;
    private String computerName;
    private String localHostname;
    private String hostname;

    private String cpuBrand;
    private Integer cpuPhysicalCores;
    private Integer cpuLogicalCores;
    private Integer cpuSockets;
    private Long physicalMemory;
    private String arch;

    private String boardVendor;
    private String boardModel;
    private String boardVersion;
    private String boardSerial;

    private String osName;
    private String osBuild;
    private Integer osMajor;
    private Integer osMinor;
    private Integer osPatch;

    public String getExternalKey() {
        return externalKey;
    }

    public void setExternalKey(String externalKey) {
        this.externalKey = externalKey;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getAssetType() {
        return assetType;
    }

    public void setAssetType(String assetType) {
        this.assetType = assetType;
    }

    public String getOwner() {
        return owner;
    }

    public void setOwner(String owner) {
        this.owner = owner;
    }

    public String getNote() {
        return note;
    }

    public void setNote(String note) {
        this.note = note;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getPlatform() {
        return platform;
    }

    public void setPlatform(String platform) {
        this.platform = platform;
    }

    public String getOsVersion() {
        return osVersion;
    }

    public void setOsVersion(String osVersion) {
        this.osVersion = osVersion;
    }

    public String getSystemUuid() {
        return systemUuid;
    }

    public void setSystemUuid(String systemUuid) {
        this.systemUuid = systemUuid;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getHardwareVendor() {
        return hardwareVendor;
    }

    public void setHardwareVendor(String hardwareVendor) {
        this.hardwareVendor = hardwareVendor;
    }

    public String getHardwareModel() {
        return hardwareModel;
    }

    public void setHardwareModel(String hardwareModel) {
        this.hardwareModel = hardwareModel;
    }

    public String getHardwareVersion() {
        return hardwareVersion;
    }

    public void setHardwareVersion(String hardwareVersion) {
        this.hardwareVersion = hardwareVersion;
    }

    public String getComputerName() {
        return computerName;
    }

    public void setComputerName(String computerName) {
        this.computerName = computerName;
    }

    public String getLocalHostname() {
        return localHostname;
    }

    public void setLocalHostname(String localHostname) {
        this.localHostname = localHostname;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public String getCpuBrand() {
        return cpuBrand;
    }

    public void setCpuBrand(String cpuBrand) {
        this.cpuBrand = cpuBrand;
    }

    public Integer getCpuPhysicalCores() {
        return cpuPhysicalCores;
    }

    public void setCpuPhysicalCores(Integer cpuPhysicalCores) {
        this.cpuPhysicalCores = cpuPhysicalCores;
    }

    public Integer getCpuLogicalCores() {
        return cpuLogicalCores;
    }

    public void setCpuLogicalCores(Integer cpuLogicalCores) {
        this.cpuLogicalCores = cpuLogicalCores;
    }

    public Integer getCpuSockets() {
        return cpuSockets;
    }

    public void setCpuSockets(Integer cpuSockets) {
        this.cpuSockets = cpuSockets;
    }

    public Long getPhysicalMemory() {
        return physicalMemory;
    }

    public void setPhysicalMemory(Long physicalMemory) {
        this.physicalMemory = physicalMemory;
    }

    public String getArch() {
        return arch;
    }

    public void setArch(String arch) {
        this.arch = arch;
    }

    public String getBoardVendor() {
        return boardVendor;
    }

    public void setBoardVendor(String boardVendor) {
        this.boardVendor = boardVendor;
    }

    public String getBoardModel() {
        return boardModel;
    }

    public void setBoardModel(String boardModel) {
        this.boardModel = boardModel;
    }

    public String getBoardVersion() {
        return boardVersion;
    }

    public void setBoardVersion(String boardVersion) {
        this.boardVersion = boardVersion;
    }

    public String getBoardSerial() {
        return boardSerial;
    }

    public void setBoardSerial(String boardSerial) {
        this.boardSerial = boardSerial;
    }

    public String getOsName() {
        return osName;
    }

    public void setOsName(String osName) {
        this.osName = osName;
    }

    public String getOsBuild() {
        return osBuild;
    }

    public void setOsBuild(String osBuild) {
        this.osBuild = osBuild;
    }

    public Integer getOsMajor() {
        return osMajor;
    }

    public void setOsMajor(Integer osMajor) {
        this.osMajor = osMajor;
    }

    public Integer getOsMinor() {
        return osMinor;
    }

    public void setOsMinor(Integer osMinor) {
        this.osMinor = osMinor;
    }

    public Integer getOsPatch() {
        return osPatch;
    }

    public void setOsPatch(Integer osPatch) {
        this.osPatch = osPatch;
    }
}