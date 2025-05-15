package com.scontrol.auth.provider.ldap.store;

import java.util.List;

public class LdapServerConfigDTO {

    private String domainName;
    private List<String> ipAddress;
    private String port;
    private String validationQuery;
    private String baseDn;
    private String userObjectClasses;
    private String rdnLDAPAttribute;
    private String uuidLDAPAttribute;
    private String customUserSearchFilter;
    private String usernameLDAPAttribute;
    private String ldapProtocol;
    private String readTimeout;
    private String connectTimeout;

    LdapServerConfigDTO(String domainName, List<String> ipAddress, String port, String validationQuery, String baseDn, String userObjectClasses, String rdnLDAPAttribute, String uuidLDAPAttribute, String customUserSearchFilter, String usernameLDAPAttribute, String ldapProtocol, String readTimeout, String connectTimeout) {
        this.domainName = domainName;
        this.ipAddress = ipAddress;
        this.port = port;
        this.validationQuery = validationQuery;
        this.baseDn = baseDn;
        this.userObjectClasses = userObjectClasses;
        this.rdnLDAPAttribute = rdnLDAPAttribute;
        this.uuidLDAPAttribute = uuidLDAPAttribute;
        this.customUserSearchFilter = customUserSearchFilter;
        this.usernameLDAPAttribute = usernameLDAPAttribute;
        this.ldapProtocol = ldapProtocol;
        this.readTimeout = readTimeout;
        this.connectTimeout = connectTimeout;
    }

    public static LdapServerConfigBuilder builder() {
        return new LdapServerConfigBuilder();
    }

    public String getDomainName() {
        return this.domainName;
    }

    public List<String> getIpAddress() {
        return this.ipAddress;
    }

    public String getPort() {
        return this.port;
    }

    public String getValidationQuery() {
        return this.validationQuery;
    }

    public String getBaseDn() {
        return this.baseDn;
    }

    public String getUserObjectClasses() {
        return this.userObjectClasses;
    }

    public String getRdnLDAPAttribute() {
        return this.rdnLDAPAttribute;
    }

    public String getUuidLDAPAttribute() {
        return this.uuidLDAPAttribute;
    }

    public String getCustomUserSearchFilter() {
        return this.customUserSearchFilter;
    }

    public String getUsernameLDAPAttribute() {
        return this.usernameLDAPAttribute;
    }

    public String getLdapProtocol() {
        return this.ldapProtocol;
    }

    public String getReadTimeout() {
        return readTimeout;
    }

    public String getConnectTimeout() {
        return connectTimeout;
    }


    public static class LdapServerConfigBuilder {
        private String domainName;
        private List<String> ipAddress;
        private String port;
        private String validationQuery;
        private String baseDn;
        private String userObjectClasses;
        private String rdnLDAPAttribute;
        private String uuidLDAPAttribute;
        private String customUserSearchFilter;
        private String usernameLDAPAttribute;
        private String ldapProtocol;
        private String connectTimeout;
        private String readTimeout;

        LdapServerConfigBuilder() {
        }

        public LdapServerConfigBuilder domainName(String domainName) {
            this.domainName = domainName;
            return this;
        }

        public LdapServerConfigBuilder ipAddress(List<String> ipAddress) {
            this.ipAddress = ipAddress;
            return this;
        }

        public LdapServerConfigBuilder port(String port) {
            this.port = port;
            return this;
        }

        public LdapServerConfigBuilder validationQuery(String validationQuery) {
            this.validationQuery = validationQuery;
            return this;
        }

        public LdapServerConfigBuilder baseDn(String baseDn) {
            this.baseDn = baseDn;
            return this;
        }

        public LdapServerConfigBuilder userObjectClasses(String userObjectClasses) {
            this.userObjectClasses = userObjectClasses;
            return this;
        }

        public LdapServerConfigBuilder rdnLDAPAttribute(String rdnLDAPAttribute) {
            this.rdnLDAPAttribute = rdnLDAPAttribute;
            return this;
        }

        public LdapServerConfigBuilder uuidLDAPAttribute(String uuidLDAPAttribute) {
            this.uuidLDAPAttribute = uuidLDAPAttribute;
            return this;
        }

        public LdapServerConfigBuilder customUserSearchFilter(String customUserSearchFilter) {
            this.customUserSearchFilter = customUserSearchFilter;
            return this;
        }

        public LdapServerConfigBuilder usernameLDAPAttribute(String usernameLDAPAttribute) {
            this.usernameLDAPAttribute = usernameLDAPAttribute;
            return this;
        }

        public LdapServerConfigBuilder ldapProtocol(String ldapProtocol) {
            this.ldapProtocol = ldapProtocol;
            return this;
        }

        public LdapServerConfigBuilder connectTimeout(String connectTimeout) {
            this.connectTimeout = connectTimeout;
            return this;
        }

        public LdapServerConfigBuilder readTimeout(String readTimeout) {
            this.readTimeout = readTimeout;
            return this;
        }

        public LdapServerConfigDTO build() {
            return new LdapServerConfigDTO(this.domainName, this.ipAddress, this.port, this.validationQuery, this.baseDn, this.userObjectClasses, this.rdnLDAPAttribute, this.uuidLDAPAttribute, this.customUserSearchFilter, this.usernameLDAPAttribute, this.ldapProtocol, this.readTimeout, this.connectTimeout);
        }

        public String toString() {
            return "LdapServerConfig.LdapServerConfigBuilder(domainName=" + this.domainName + ", ipAddress=" + this.ipAddress + ", port=" + this.port + ", validationQuery=" + this.validationQuery + ", baseDn=" + this.baseDn + ", userObjectClasses=" + this.userObjectClasses + ", rdnLDAPAttribute=" + this.rdnLDAPAttribute + ", uuidLDAPAttribute=" + this.uuidLDAPAttribute + ", customUserSearchFilter=" + this.customUserSearchFilter + ", usernameLDAPAttribute=" + this.usernameLDAPAttribute + ", ldapProtocol=" + this.ldapProtocol + ", readTimeout=" + this.readTimeout + ", connectTimeout=" + this.connectTimeout + ")";
        }
    }
}

