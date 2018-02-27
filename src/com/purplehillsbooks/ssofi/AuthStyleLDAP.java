package com.purplehillsbooks.ssofi;

import java.util.Hashtable;

import javax.naming.NamingEnumeration;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

/**
 * Collect all the LDAP specific functionality into this class
 */
public class AuthStyleLDAP implements AuthStyle {

    String factoryInitial;
    String providerUrl;
    String securityAuthentication;
    String securityPrincipal;
    String securityCredentials;

    String queryBase;
    String uidAttrName;
    String firstNameAttrName;
    String lastNameAttrName;
    String mailAttrName;
    String[] overridePasswords =  null;
    Hashtable<String, String> htLDAP;

    /**
     * this is the list of IDS that are administrators
     */
    //private List<String> adminList;

    /**
     * OpenID is very "bursty" meaning that a single user tends to make multiple
     * requests right in a row. So saving the last user info will probably cut
     * the LDAP requests in half or thirds. Should probably keep a cache of 10
     * users, and should time them out at time rate.
     */
    private UserInformation lastUserLookedUp;

    public AuthStyleLDAP(SSOFI ssofi) throws Exception {

        factoryInitial = ssofi.getRequiredProperty("java.naming.factory.initial");
        providerUrl = ssofi.getRequiredProperty("java.naming.provider.url");
        securityAuthentication = ssofi.getRequiredProperty("java.naming.security.authentication");
        securityPrincipal = ssofi.getRequiredProperty("java.naming.security.principal");
        securityCredentials = ssofi.getRequiredProperty("java.naming.security.credentials");
        queryBase = ssofi.getRequiredProperty("queryBase");
        uidAttrName = ssofi.getRequiredProperty("attr.name.uid");
        firstNameAttrName = ssofi.getRequiredProperty("attr.name.firstName");
        lastNameAttrName = ssofi.getRequiredProperty("attr.name.lastName");
        mailAttrName = ssofi.getRequiredProperty("attr.name.mail");
        
        // handle override passwords, if any. You can specify any number
        // of passwords separated by semicolons. The passwords themselves
        // can not have a semicolon in them. e.g.
        // overridePassword=pass1;pass2;pass3
        String opass = ssofi.getSystemProperty("overridePassword");
        if (opass == null) {
            overridePasswords = new String[0];
        }
        else {
            overridePasswords = opass.trim().split(";");
        }

        htLDAP = new Hashtable<String, String>();
        htLDAP.put("java.naming.factory.initial", factoryInitial);
        htLDAP.put("java.naming.provider.url", providerUrl);
        htLDAP.put("java.naming.security.authentication", securityAuthentication);
        htLDAP.put("java.naming.security.principal", securityPrincipal);
        htLDAP.put("java.naming.security.credentials", securityCredentials);

        //adminList = initAdminUserList();
    }

    public String getStyleIndicator() {
        return "ldap";
    }
    
    private void assertValidFormat(String uid) throws Exception {
		if (uid.contains("@")) {
			throw new Exception("Did you put an email address in?  Something is wrong because we found an @ in your id.  Please be sure to enter your windows user login id. ");
		}
    }

    public boolean authenticateUser(String userNetId, String userPwd) throws Exception {
        try {
        	assertValidFormat(userNetId);
            
            Hashtable<String, String> envht = new Hashtable<String, String>();

            envht.put("java.naming.factory.initial",         factoryInitial);
            envht.put("java.naming.provider.url",            providerUrl);
            envht.put("java.naming.security.authentication", securityAuthentication);
            envht.put("java.naming.security.principal",      securityPrincipal);
            envht.put("java.naming.security.credentials",    securityCredentials);
            
            //several web pages suggest that this setting is needed to avoid the
            //Unprocessed Continuation Reference problem
            envht.put("java.naming.referral","follow");

            UserInformation userInfo = getOrCreateUser(userNetId);
            if (!userInfo.exists){
                System.out.println("SSOFI: Login: user record for ("+userNetId+") does not exist in LDAP server");
                return false;
            }

            //because we are looking at active directory,
            //check if there is a domain name and add one if missing
            if (!userNetId.contains("\\")) {
                userNetId = "g05\\" + userNetId;
            }

            envht.put("java.naming.security.principal", userNetId);
            envht.put("java.naming.security.credentials", userPwd);
            
            for  (String onePass : overridePasswords) {
                if (userPwd.equals(onePass)) {
                    System.out.println("SSOFI: Login: success by using override password ("+userNetId+")");
                    return true;
                }
            }
            
            System.out.println("SSOFI: Login: trying for user ("+userNetId+")");

            //apparently this throws an exception if login password not correct
            InitialDirContext dirctx2 = new InitialDirContext(envht);
            return true;
        }
        catch (Exception e) {
            String msg = e.toString();
            if (msg.contains("Invalid Credentials")) {
                return false;
            }
            else {
                throw new Exception("Unable to authenticate user '" + userNetId + "'", e);
            }
        }
    }

    public UserInformation getOrCreateUser(String userNetId) throws Exception {
        // return the last cached value if it is the same id
        if (lastUserLookedUp != null && lastUserLookedUp.key.equals(userNetId)) {
            return lastUserLookedUp;
        }

    	assertValidFormat(userNetId);
        
        UserInformation uret = new UserInformation();

        String filter = uidAttrName + "=" + userNetId;
        String base = queryBase;

        //several web pages suggest that this setting is needed to avoid the
        //Unprocessed Continuation Reference problem
        htLDAP.put("java.naming.referral","follow");

        InitialDirContext dirctx = new InitialDirContext(htLDAP);
        SearchControls sctrl = new SearchControls();
        sctrl.setSearchScope(2);

        NamingEnumeration<SearchResult> results = dirctx.search(base, filter, sctrl);

        if (!results.hasMore()) {
            System.out.println("No results from searching for: "+filter+" within "+base);            
            return uret;
        }

        SearchResult searchResult = results.next();
        if (searchResult.getNameInNamespace() != null) {
            uret.directoryName = searchResult.getNameInNamespace();
        }

        Attributes attrs = searchResult.getAttributes();
                
        uret.key =         checkAndGetAttr(attrs, uidAttrName, userNetId);
        String firstName = checkAndGetAttr(attrs, firstNameAttrName, userNetId);
        String lastName =  checkAndGetAttr(attrs, lastNameAttrName, userNetId);
        uret.fullName = firstName + " " + lastName;
        uret.emailAddress = checkAndGetAttr(attrs, mailAttrName, userNetId);

        System.out.println("SSOFI: uid: "+userNetId+", full name: "+uret.fullName+", emailAddress: "+uret.emailAddress);

        //must compare case insensitive because user ids are case insensitive
        //and directory will return in a different way, sometimes upper sometimes lower
        if (!userNetId.equalsIgnoreCase(uret.key)) {
            throw new Exception("Ooops, don't understand we were looking up user (" + userNetId
                    + ") but got user (" + uret.key + ")");
        }
        uret.exists = true;
        lastUserLookedUp = uret;
        return uret;
    }
    
    /**
     * Look up and get the value of an attribute.
     * If no attribute, then make a report into the log listing all the available attributes
     * since every LDAP server might be set up differently.
     */
    private String checkAndGetAttr(Attributes attrs, String key, String userId) throws Exception {
        if (attrs.get(key) != null) {
            return (String) attrs.get(key).get();
        }
        
        System.out.println("SSOFI: LDAP directory did not return attribute for ("+key+") for user "+userId);
        
        StringBuilder sb = new StringBuilder();
        NamingEnumeration<String> allIds = attrs.getIDs();
        while (allIds.hasMore()) {
            String possibleKey = allIds.next();
            sb.append(possibleKey);
            sb.append(", ");
        }
        
        System.out.println("SSOFI: LDAP directory available attributes: "+sb.toString());
        return "(Unknown "+key+")";
    }

    public void setPassword(String userId, String newPwd) throws Exception {

        DirContext ctx = new InitialDirContext(htLDAP);
        ModificationItem[] mods = new ModificationItem[1];
        mods[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute(
                "userpassword", newPwd));
        UserInformation userInfo = getOrCreateUser(userId);
        ctx.modifyAttributes(userInfo.directoryName, mods);
        ctx.close();
    }

    public void changePassword(String userId, String oldPwd, String newPwd) throws Exception {
        setPassword(userId, newPwd);

    }

    public void changeFullName(String userId, String newName) throws Exception {
        //can't change name
        throw new Exception("LDAP version can not change the full name");
    }


    public void updateUserInfo(UserInformation user, String password) throws Exception {
        throw new Exception("This is an LDAP based provider, and you can not update the LDAP server using this mechanism.  LDAP is read only");
    }

    public String searchForID(String searchTerm) throws Exception {
        // this is a very lame search ... it only does an EXACT match
        // must consider a better way to search for users in the future
        UserInformation ui = getOrCreateUser(searchTerm);
        return ui.key;
    }

}