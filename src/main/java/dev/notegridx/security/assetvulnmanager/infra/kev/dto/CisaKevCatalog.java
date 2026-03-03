package dev.notegridx.security.assetvulnmanager.infra.kev.dto;

import java.util.List;

public class CisaKevCatalog {
    public String title;
    public String catalogVersion;
    public String dateReleased;
    public Integer count;
    public List<KevItem> vulnerabilities;

    public static class KevItem {
        public String cveID;
        public String dateAdded;
        public String dueDate;
        public String knownRansomwareCampaignUse;

        public String vendorProject;
        public String product;
        public String vulnerabilityName;
        public String shortDescription;

        public String requiredAction;
        public List<String> references;
        public String notes;
    }
}