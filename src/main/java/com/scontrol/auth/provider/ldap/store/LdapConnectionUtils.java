package com.scontrol.auth.provider.ldap.store;

import com.scontrol.auth.provider.user.LDAPStorageProviderCimp;
import org.jboss.logging.Logger;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.util.*;

import static com.scontrol.auth.provider.user.LDAPStorageProviderCimp.CIMP_TAG;
import static com.scontrol.auth.provider.user.LDAPStorageProviderCimp.EMPTY_STRING;

public class LdapConnectionUtils {
    public static final String MEMBER_OF = "memberOf";
    public static final String MAIL = "mail";
    public static Hashtable<String, String> ENV = new Hashtable<>();
    private static final Logger logger = Logger.getLogger(LdapConnectionUtils.class);

//    public static Attributes connect2LdapSearchUser(String userName, String password, String domainIp, String search_base, String port) throws NamingException {
//        String searchFilter = "(&(cn="+userName+")(objectclass=person)(objectclass=organizationalPerson)(objectclass=user))";
//        return connect2LdapSearchUser( userName, password, domainIp, search_base, port, searchFilter);
//    }

    public static Map<String, Set<String>> connect2LdapSearchUser(String userName, String password, List<String> domainIps, String search_base, String port, String searchFilter) throws NamingException {
        String usernameLDAPattribute = "CN";
        String ldapProtocol = "ldap";
        return connect2LdapSearchUser( userName, password, domainIps, search_base, port, searchFilter, usernameLDAPattribute, ldapProtocol);
    }

    public static Map<String, Set<String>> connect2LdapSearchUser(String userName, String password, List<String> domainIps,
                                                                  String baseDN, String port, String searchFilter,
                                                                  String usernameLDAPattribute, String ldapProtocol) throws NamingException {

        for (String domainIp : domainIps) {
            setEnv(userName, password, domainIp, baseDN, port, usernameLDAPattribute, ldapProtocol);

            // Create initial context
            try {
                DirContext ctx = new InitialDirContext(ENV); //Authenticated

                SearchControls searchCtls = new SearchControls();
                // Specify the search scope
                searchCtls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                NamingEnumeration<?> results = ctx.search(baseDN, searchFilter, searchCtls);


                Attributes attrs;
                Set<String> mailSet = new HashSet<>(1);

                Set<String> groupsSet = new HashSet<>();
                String userDN = "";
                if (results.hasMore()) {
                    SearchResult result = (SearchResult) results.next();
                    attrs = result.getAttributes();
                    //debug
                    logger.infof("[cimp] ldap search attrs: %s", attrs.toString());

                    Attribute mailAttribute = attrs.get(MAIL);
                    String mail = getMail(mailAttribute);
                    mailSet.add(mail);

                    Attribute memberOf = attrs.get(MEMBER_OF);
                    getGroups(memberOf, groupsSet);

                    userDN = result.getNameInNamespace(); //'CN=user8d2,CN=Users,DC=cimpdomain2,DC=com'
                }
                if (groupsSet.isEmpty()) {
                    // Fallback: Search for group membership manually
                    logger.info(CIMP_TAG + "memberOf not found, using fallback search...");
                    groupsSet = getGroupMembership(ctx, baseDN, userName, userDN);
                }
                results.close();
                // Close the context when we're done
                ctx.close();
                Map<String, Set<String>> resultMap = new HashMap<>();
                resultMap.put(MAIL, mailSet);
                resultMap.put(MEMBER_OF, groupsSet);
                return resultMap;
            } catch (NamingException e) {
                logger.error(CIMP_TAG + "Error connect for baseDN:" + baseDN + " ip:" + domainIp + " message:" + e.getMessage());
                // continue to next server
            }
        }
        return Collections.emptyMap();
    }

    private static void getGroups(Attribute memberOf, Set<String> groupsSet) throws NamingException {
        if (memberOf != null) {
            NamingEnumeration<?> groupEnum = memberOf.getAll();
            while (groupEnum.hasMore()) {
                groupsSet.add(groupEnum.next().toString());
            }
        }
    }

    private static String getMail(Attribute mailAttribute) {
        String mail= EMPTY_STRING;
        if (mailAttribute != null) {
            mail = mailAttribute.toString();
            int count = mail.indexOf(": ")+2;
            if (mail.length()>count) {
                mail = mail.substring(count);
            }
        }
        return mail;
    }

    private static void setEnv(String userName, String password, String domainIp, String search_base, String port, String usernameLDAPattribute, String ldapProtocol) {
        ENV.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        ENV.put(Context.SECURITY_AUTHENTICATION, "simple");
        ENV.put(Context.SECURITY_PRINCIPAL, usernameLDAPattribute + "=" + userName + "," + search_base);  // Connected to LDAP successfully with 'DC=cimpdomain1,DC=com'
        ENV.put(Context.SECURITY_CREDENTIALS, password);
//        String ldapProtocol = "ldap";
        ENV.put(Context.PROVIDER_URL, ldapProtocol + "://" + domainIp + ":" + port);
        // ENV.put(Context.PROVIDER_URL, "ldaps://" + domainIp+ ":" + port); // LDAPS

//        String usernameLDAPattribute  = "CN"; = "uid"; // 'Username: uid=john,ou=users,dc=example,dc=org'
        // LDAPS-specific: Trust the server's SSL certificate (Java trusts by default, but you may customize this)
        // Optionally, set: javax.net.ssl.trustStore and trustStorePassword if using custom certs

        //debug
        logger.infof("[cimp] connect2LdapSearchUser setEnv "+ENV.toString());
    }


//    New ActiveDirectoryAuthenticator/**/ {
//
//    public static Set<String> authenticateAndGetGroups(List<LdapServer> servers, String baseDN, String username, String password) {
//        for (LdapServer server : servers) {
//            String url = "ldap://" + server.ipAddress + ":" + server.port;
//            System.out.println("Connecting to: " + url);
//
//            Hashtable<String, String> env = new Hashtable<>();
//            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
//            env.put(Context.PROVIDER_URL, url + "/" + baseDN);
//            env.put(Context.SECURITY_AUTHENTICATION, "simple");
//            env.put(Context.SECURITY_PRINCIPAL, username);
//            env.put(Context.SECURITY_CREDENTIALS, password);
//            env.put("com.sun.jndi.ldap.connect.timeout", "10000");
//
//            try {
//                DirContext ctx = new InitialDirContext(env);
//                System.out.println("Authenticated!");
//
//                // Try to get memberOf attribute first
//                String filter = "(sAMAccountName=" + username + ")";
//                SearchControls ctrls = new SearchControls();
//                ctrls.setSearchScope(SearchControls.SUBTREE_SCOPE);
//                ctrls.setReturningAttributes(new String[]{MEMBER_OF});
//
//                NamingEnumeration<SearchResult> results = ctx.search(baseDN, filter, ctrls);
//                Set<String> groups = new HashSet<>();
//
//                if (results.hasMore()) {
//                    Attributes attrs = results.next().getAttributes();
//                    Attribute memberOf = attrs.get(MEMBER_OF);
//
//                    if (memberOf != null) {
//                        NamingEnumeration<?> groupEnum = memberOf.getAll();
//                        while (groupEnum.hasMore()) {
//                            groups.add(groupEnum.next().toString());
//                        }
//                        ctx.close();
//                        return groups;
//                    }
//                }
//
//                // Fallback: Search for group membership manually
//                System.out.println("memberOf not found, using fallback search...");
//                groups = getGroupMembership(ctx, baseDN, username);
//                ctx.close();
//                return groups;
//
//            } catch (Exception e) {
//                System.out.println("Error: " + e.getMessage());
//                // continue to next server
//            }
//        }
//        return Collections.emptySet();
//    }

    private static Set<String> getGroupMembership(DirContext ctx, String baseDN, String username, String userDN) throws NamingException {
        String userFilter = "(sAMAccountName=" + username + ")";
        SearchControls userSearchCtrls = new SearchControls();
        userSearchCtrls.setSearchScope(SearchControls.SUBTREE_SCOPE);
//        NamingEnumeration<SearchResult> userResults = ctx.search(baseDN, userFilter, userSearchCtrls);
//
//        if (!userResults.hasMore()) {
//            return Collections.emptySet();
//        }
//        String userDN = userResults.next().getNameInNamespace();

        String groupFilter = "(&(objectClass=group)(member=" + userDN + "))";
        SearchControls groupCtrls = new SearchControls();
        groupCtrls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        NamingEnumeration<SearchResult> groupResults = ctx.search(baseDN, groupFilter, groupCtrls);

        final Set<String> groups = new HashSet<>();
        while (groupResults.hasMore()) {
            Attributes attrs = groupResults.next().getAttributes();
            Attribute cn = attrs.get("cn");
            if (cn != null) groups.add((String) cn.get());
        }
        return groups;
    }

    // Helper class for server info
    public static class LdapServer {
        public String ipAddress;
        public int port;

        public LdapServer(String ipAddress, int port) {
            this.ipAddress = ipAddress;
            this.port = port;
        }
    }


}
