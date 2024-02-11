package com.purplehillsbooks.ssofi;

import java.io.File;
import java.io.FileInputStream;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Properties;
import java.util.Set;

import jakarta.servlet.ServletContext;

import com.purplehillsbooks.json.JSONException;
import com.purplehillsbooks.streams.SSLPatch;
import com.purplehillsbooks.streams.StreamHelper;

/**
 * This is the core singleton class that represents the configuration
 * of the SSOFI server.  Everything in this object is common
 * to all users, all sessions, all requests.  Generally, this is where
 * all of the configuration settings should be, as well as any common
 * static utlity service.
 */
public class SSOFI {

    private ServletContext sc;
    private Properties config;
    private File dataFolder;
    private File configFile;
    private TextEncrypter textEncrypter;

    public boolean initialized = false;
    public Exception initFailure = null;

    // reconfigurable base address of the application (for proxy cases)
    public String baseURL;

    // this is internal address of the root of application (on this server)
    // use this for decomposing request URLs
    public String rootURL;
    public String knownAssetPath;

    public AuthStyle authStyle = null;
    public SessionHandlerFile sHand = null;
    public EmailHandler emailHandler = null;
    public SecurityHandler securityHandler = null;
    public EmailTokenManager tokenManager = null;

    public int sessionDurationSeconds = 2500000;   //30 days
    public boolean isLDAPMode = false;

    public static boolean USE_SESSION_COOKIE = true;

    public static synchronized SSOFI getSSOFI(ServletContext sc) {
        SSOFI ssofi = (SSOFI) sc.getAttribute("SSOFI");
        if (ssofi == null) {
            ssofi = new SSOFI(sc);
            sc.setAttribute("SSOFI", ssofi);
        }
        return ssofi;
    }

    private SSOFI(ServletContext _sc) {
        try {
            sc = _sc;
            
            //initialize a text encrypter which later is used for
            //decrypting values from property files
            textEncrypter = new TextEncrypter("DESede");
            
            findInitializeDataFolder();

            //get the server id from the MAC address of this machine
            StoredUser.guidTail = generateServerId();

            // disable Java certificate validation in the SSL level
            // necessary so that bytes can be read reliably over SSL
            SSLPatch.disableSSLCertValidation();

            readConfigFile();

            String sessionDurationStr = getSystemProperty("sessionDurationSeconds");
            if (sessionDurationStr!=null) {
                int durVal = Integer.parseInt(sessionDurationStr);
                if (durVal>600) {
                    //it is not realistic to have a session duration shorter than 10 minutes
                    //so only set if we have a value greater than 600 seconds.
                    sessionDurationSeconds = durVal;
                }
            }

            sHand = new SessionHandlerFile(dataFolder, sessionDurationSeconds);

            isLDAPMode = "LDAP".equalsIgnoreCase(getSystemProperty("authStyle"));

            if (isLDAPMode) {
                authStyle = new AuthStyleLDAP(this);
            }
            else {
                // NOTE: local mode must be the DEFAULT if no setting is supplied
                authStyle = new AuthStyleLocal(sc, this);
            }

            baseURL = getRequiredProperty("baseURL").toLowerCase();

            if (!baseURL.endsWith("/")) {
                baseURL = baseURL + "/";
            }
            AuthSession.baseURL = baseURL;
            APIHelper.baseURL = baseURL;

            rootURL = getRequiredProperty("rootURL").toLowerCase();

            if (!rootURL.endsWith("/")) {
                rootURL = rootURL + "/";
            }
            knownAssetPath = rootURL + "$/";
            
            System.out.println("SSOFI: baseURL: "+baseURL);
            System.out.println("SSOFI: rootURL: "+rootURL);
            System.out.println("SSOFI: authStyle: "+authStyle.getStyleIndicator());

            File emailConfigFile = new File(dataFolder, "EmailNotification.properties");
            if (!emailConfigFile.exists()) {
                initFileFromWebInf(emailConfigFile);
            }
            if (!emailConfigFile.exists()) {
                throw new Exception(
                        "Server needs to be configured.  No email configuration file found: ("
                                + emailConfigFile.toString() + ")");
            }

            try {
                FileInputStream fisEmail = new FileInputStream(emailConfigFile);
                Properties propEmail = new Properties();
                propEmail.load(fisEmail);
                fisEmail.close();
                propEmail = decryptProperties(propEmail);
                emailHandler = new EmailHandler(this, propEmail);
            }
            catch (Exception e) {
                throw new Exception("Unable to initialize from email config file ("+emailConfigFile+")",e);
            }

            File emailTokenFile = new File(dataFolder, "EmailTokens.json");
            tokenManager = new EmailTokenManager(emailTokenFile);

            AddressParser.initialize(baseURL);

            File bipfile = new File(dataFolder, "blockedIp.txt");
            if (!bipfile.exists()) {
                bipfile.createNewFile();
            }
            String captchaPrivateKey = getSystemProperty("captchaPrivateKey");
            String captchaPublicKey = getSystemProperty("captchaPublicKey");
            securityHandler = new SecurityHandler(captchaPrivateKey, captchaPublicKey,
                    bipfile);

            initialized = true;
        }
        catch (Exception e) {
            initialized = false;
            initFailure = e;
            // get something into the log as well in case nobody accesses the
            // server
            System.out.println("\n##### ERROR DURING SSOFI PROVIDER INITIALIZATION #####");
            JSONException.traceException(e, "SSOFI PROVIDER INITIALIZATION");
            System.out.println("##### ##### #####\n");
        }
    }

    public void initFileFromWebInf(File expectedFile) throws Exception {
        String webInfPath = sc.getRealPath("/WEB-INF");
        File initFile = new File(webInfPath, expectedFile.getName());
        if (initFile.exists()) {
            StreamHelper.copyFileToFile(initFile, expectedFile);
        }
    }

    private void findInitializeDataFolder() throws Exception {
        //first we read the one config file that tells where everything else is
        String webInfPath = sc.getRealPath("/WEB-INF");
        File basicConfigFile = new File(webInfPath, "config.properties");
        if (basicConfigFile.exists()) {
            FileInputStream fis = new FileInputStream(basicConfigFile);
            Properties tprop = new Properties();
            tprop.load(fis);
            fis.close();
            String dpath = tprop.getProperty("dataFolder");
            if (dpath!=null) {
                dataFolder = new File(dpath);
            }
        }
        if (dataFolder==null) {
            dataFolder = new File("/opt/SSOFI_Sessions");
        }

        if (!dataFolder.exists()) {
            dataFolder.mkdirs();
        }
        System.out.println("SSOFI: data folder: "+dataFolder);
    }
    
    private String decryptText(String text) {
        if(text == null || text.trim().isEmpty()) {
            return text;
        }
        String myText = text.trim();
        try {
            return textEncrypter.decrypt(myText);
        } catch(Exception e) {
            return myText;
        }
    }
    
    //This method loops through all the properties and try to decrypt the value for each property
    //If the value is not an encrypted value, it simply returns the value as is
    //Although this approach may incur a small performance cost, it is more flexible than
    //hard code the names of those properties that need to be decrypted
    //This means it can handle future changes like adding a new encrypted property
    //Since this method is only called at the SSOFI initialization phase, the performance is not an issue
    private Properties decryptProperties(Properties props) {
        if(props == null) {
            return props;
        }
        Properties newProps = new Properties();
        Set<String> keys = props.stringPropertyNames();
        for(String key : keys) {
            newProps.setProperty(key, decryptText(props.getProperty(key)));
        }
        return newProps;
    }
    
    private void readConfigFile() throws Exception {
        configFile = new File(dataFolder, "config.txt");
        System.out.println("SSOFI: config file: "+configFile);
        if (!configFile.exists()) {
            initFileFromWebInf(configFile);
        }

        if (!configFile.exists()) {
            throw new Exception(
                    "Server needs to be configured.  No configuration file found: ("
                            + configFile + ")");
        }
        try {
            FileInputStream fis = new FileInputStream(configFile);
            Properties tprop = new Properties();
            tprop.load(fis);
            fis.close();
            tprop = decryptProperties(tprop);
            config = tprop;
        }
        catch(Exception e) {
            throw new Exception("Unable to read config file ("+configFile+")", e);
        }
    }

    public String getSystemProperty(String key) {
        return config.getProperty(key);
    }
    public String getRequiredProperty(String key) throws Exception {
        String val = config.getProperty(key);
        if (val == null) {
            throw new Exception("Must have a setting for '" + key
                    + "' in the configuration file ("+configFile+")");
        }
        return val;
    }

    public File getDataFolder() {
        return dataFolder;
    }

    static long lastKey = 0;
    static char[] thirtySix = new char[] {'0','1','2','3','4','5','6','7','8','9',
        'a','b','c','d','e','f','g','h','i','j', 'k','l','m','n','o','p','q','r',
        's','t','u','v','w','x','y','z'};
    /**
    * Generates a value based on the current mac address of the
    * current server.  This gives us a unique value for the server
    * from which to build unique user ids.
    */
    public synchronized static String generateServerId() throws Exception {

        InetAddress ip = InetAddress.getLocalHost();
        NetworkInterface network = NetworkInterface.getByInetAddress(ip);
        if (network==null) {
            throw new Exception("Unable to identify a network interface with the address "+ip);
        }
        byte[] mac = network.getHardwareAddress();
        long macValue = 0;
        if (mac==null) {
            macValue = System.currentTimeMillis();
            //throw new Exception("The method 'getHardwareAddress' was not able to return an actual mac address.  Something is wrong with network configuration");
        }
        else {
            for (byte oneByte : mac) {
                macValue = (macValue<<8) + (oneByte+256)%256;
            }
        }
        if (macValue==0) {
            //throw new Exception("Unable to get the MAC address");
            //not sure this is a good idea, but make up a timestamp as a unique id for now
            macValue = System.currentTimeMillis();
        }
        //now convert timestamp into cryptic alpha string
        StringBuffer res = new StringBuffer(10);
        while (macValue>0) {
            res.append(thirtySix[(int)(macValue % 36)]);
            macValue = macValue / 36;
        }
        return res.toString();
    }



    public String getSSOFISessionId(WebRequest wr) {

        //cookies can not be trusted because Chrome is putting too many restrictions
        //and the documented methods don't seem to be working.   But we don't need
        //to use cookies, we just need a clear session id token that can not
        //be easily spoofed and rotates frequently enough.
        //the URL 'ss' parameter will take precedence over the cookie.
        String sessionId = wr.request.getParameter("ss");


        if (sessionId==null) {
            //we did not find an 'ss' parameter.  In this case it could be the regular
            //web UI wanting something served, and in this case use the regular
            //session provided by TomCat associated with the JSession.
            sessionId = wr.getSessionAttribute("SSOFISession");

        }
        if (sessionId==null) {
            //so, 'ss' parameter and no java session.  In this case use the cookie
            //for backward compatibility.   We are not setting this cookie any more
            //but if it is there, use it.
            sessionId = wr.findCookieValue("SSOFISession");
        }
        if (sessionId == null || sessionId.length() < 10) {
            //if the value is missing or look illegitimate, then throw it away, and
            //generate a new session.
            sessionId = createSSOFISessionId(wr);
        }

        //Store the session in the java session so that the normal UI can leverage
        //that session reliably why the user is actually on the SSOFI site.
        wr.setSessionAttribute("SSOFISession", sessionId);
        if (USE_SESSION_COOKIE) {
            wr.setCookieSecure("SSOFISession", sessionId);
        }
        else {
            //clear out the cookie so that the testing cases are not fooled
            wr.setCookieSecure("SSOFISession", "XYZ");
        }
        return sessionId;
    }
    /**
     * Generate a new, different session ID.
     * This should be called immediately after logout so that on the next
     * request the browser is using a new session.
     * The previous session object should be destroyed as well.
     */
    public static String createSSOFISessionId(WebRequest wr) {
        String sessionId = "S" + IdGenerator.createMagicNumber();

        wr.setSessionAttribute("SSOFISession", sessionId);

        {
            //just testing
            String nextId = wr.getSessionAttribute("SSOFISession");
            if (!nextId.equals(sessionId)) {
                System.out.println("SSOFI: FAILURE to set the session id: "+nextId);
            }

        }
        wr.setSessionAttribute("SSOFISession", sessionId);
        if (USE_SESSION_COOKIE) {
            wr.setCookieSecure("SSOFISession",sessionId);
        }
        return sessionId;
    }


}
