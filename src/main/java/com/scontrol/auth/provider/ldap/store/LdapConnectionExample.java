package com.scontrol.auth.provider.ldap.store;

//import com.baeldung.com.scontrol.auth.provider.user.LDAPQueryCimp;
//import com.baeldung.com.scontrol.auth.provider.user.LDAPUtilsCimp;
//import org.keycloak.models.LDAPConstants;
//import org.keycloak.models.RealmModel;
//import org.keycloak.storage.ldap.idm.model.LDAPObject;
//import org.keycloak.storage.ldap.idm.query.Condition;
//import org.keycloak.storage.ldap.idm.query.EscapeStrategy;
//import org.keycloak.storage.ldap.idm.query.internal.LDAPQueryConditionsBuilder;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.directory.Attributes;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

public class LdapConnectionExample {
    public static final String SEARCH_BASE = "DC=cimpdomain1,DC=com";
//    static public String userName = "user1 d1";
//    static public String password = "123qweasd";
    static public String userName = "user3";
    static public String password = "1234qwer";
    static public String searchFilter = "(&(cn="+userName+")(objectclass=person)(objectclass=organizationalPerson)(objectclass=user))";
    //    static String userName = "Administrator";
//    static String password = "P@ssword";
//    static String searchFilter = "(&(cn="+userName+")(objectclass=person)(objectclass=organizationalPerson)(objectclass=user))" ;
    public static final String domainIP = "192.168.1.18";

    public static void main1(String[] args) {

//ldap://192.168.1.18:389
        try {
            LdapContext context = connectToLdap(userName, password, domainIP);
            System.out.println("Connected to LDAP successfully.");
            // Optionally, you can perform further operations here
            Attributes attributes = searchUser(context, SEARCH_BASE, searchFilter);

            System.out.println("Found user: " + attributes.get("cn"));
            System.out.println(attributes);
            context.close();
        } catch (NamingException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        try {
            Attributes attributes = LdapConnectionUtils.connect2LdapSearchUser(userName, password, domainIP, SEARCH_BASE);
            System.out.println("Found user: " + attributes.get("cn"));
            System.out.println(attributes);      

        } catch (NamingException e) {
            e.printStackTrace();
        }
    }

    public static LdapContext connectToLdap(String userName, String password, String domainName) throws NamingException {
        return new InitialLdapContext(LdapConnectionUtils.ENV, null);
    }

    // Optional: Example method to search for a user
    public static Attributes searchUser(LdapContext context, String searchBase, String searchFilter) throws NamingException {
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        NamingEnumeration<SearchResult> results = context.search(searchBase, searchFilter, searchControls);

        while (results.hasMore()) {
            SearchResult searchResult = results.next();
            return searchResult.getAttributes();

        }
        return null;
    }

//    public LDAPObject loadLDAPUserByUsername(RealmModel realm, String username){
//        try (LDAPQueryCimp ldapQuery = LDAPUtilsCimp.createQueryForUserSearch(this, realm)) {
//            LDAPQueryConditionsBuilder conditionsBuilder = new LDAPQueryConditionsBuilder();
//
//            String usernameMappedAttribute = getUsernameLdapAttribute(); //this.ldapIdentityStore.getConfig().getUsernameLdapAttribute();
//            Condition usernameCondition = conditionsBuilder.equal(usernameMappedAttribute, username, EscapeStrategy.DEFAULT);
//            ldapQuery.addWhereCondition(usernameCondition);
//
//            LDAPObject ldapUser = ldapQuery.getFirstResult();
//            if (ldapUser == null) {
//                return null;
//            }
//
//            return ldapUser;
//        }
//    };

//    public String getUsernameLdapAttribute() {
//        return LDAPConstants.CN;
//        String username = config.getFirst(LDAPConstants.USERNAME_LDAP_ATTRIBUTE);
//        if (username == null) {
//            username = isActiveDirectory() ? LDAPConstants.CN : LDAPConstants.UID;
//        }
//        return username;
//    }
}
//In this example:
//
// 1 Connecting to LDAP:
//
//The connectToLdap method establishes a connection to the LDAP server using the provided userName, password, and domainName.
//The ldapUrl is constructed from the domainName.

// 2 Performing Operations (Optional):
//
//The searchUser method demonstrates how to perform a search in the LDAP directory. This method is optional and can be customized based on your needs.
//The searchBase is the base DN (Distinguished Name) where the search should start.
//The searchFilter is the LDAP search filter (e.g., "(objectClass=user)").
//Replace "yourUserName", "yourPassword", and "yourDomainName" with actual values to test the connection.
// Adjust the searchBase and searchFilter parameters in the searchUser method to suit your directory structure if you want to perform searches.

//----------------------------------------------------------
//result:
//{displayname=displayName: user1 d1, givenname=givenName: user1, samaccounttype=sAMAccountType: 805306368, primarygroupid=primaryGroupID: 513,
// objectclass=objectClass: top, person, organizationalPerson, user, badpasswordtime=badPasswordTime: 133606907935149410,
// objectcategory=objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cimpdomain1,DC=com, mail=mail: user1keycloak@gmail.com, cn=cn: user1 d1,
// useraccountcontrol=userAccountControl: 512, userprincipalname=userPrincipalName: user1@cimpdomain1.com, dscorepropagationdata=dSCorePropagationData: 16010101000000.0Z, codepage=codePage: 0, distinguishedname=distinguishedName: CN=user1 d1,CN=Users,DC=cimpdomain1,DC=com, whenchanged=whenChanged: 20240528233725.0Z, whencreated=whenCreated: 20240516174042.0Z, pwdlastset=pwdLastSet: 133614130453957618, logoncount=logonCount: 0, accountexpires=accountExpires: 9223372036854775807, lastlogoff=lastLogoff: 0, lastlogontimestamp=lastLogonTimestamp: 133606908909527121, objectguid=objectGUID: �V^;�#�N����KB4�, sn=sn: d1, lastlogon=lastLogon: 133606908909527121, usnchanged=uSNChanged: 16439, usncreated=uSNCreated: 12740, objectsid=objectSid: <�s!��ƈ�T, countrycode=countryCode: 0, samaccountname=sAMAccountName: user1, instancetype=instanceType: 4,
//
//memberof=memberOf: CN=Allowed RODC Password Replication Group,CN=Users,DC=cimpdomain1,DC=com,
//badpwdcount=badPwdCount: 0, name=name: user1 d1}