package org.workcast.ssofiprovider;

import java.io.File;
import java.io.FileInputStream;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Properties;

import javax.servlet.ServletContext;

import org.workcast.streams.SSLPatch;
import org.workcast.streams.StreamHelper;

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

    public boolean initialized = false;
    public Exception initFailure = null;

    // reconfigurable base address of the application (for proxy cases)
    public String baseURL;

    // this is internal address of the root of application (on this server)
    // use this for decomposing request URLs
    public String rootURL;
    public String knownAssetPath;

    public AuthStyle authStyle = null;
    public SessionHandler sHand = null;
    public EmailHandler emailHandler = null;
    public SecurityHandler securityHandler = null;
    public EmailTokenManager tokenManager = null;

    public int sessionDurationSeconds = 2500000;   //30 days
    public boolean isLDAPMode = false;


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

            findInitializeDataFolder();

            //get the server id from the MAC address of this machine
            User.guidTail = generateServerId();

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
            e.printStackTrace(System.out);
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
            config = tprop;
        }
        catch(Exception e) {
            throw new Exception("Unable to read config file ("+configFile+")", e);
        }
        System.out.println("SSOFI: baseURL: "+config.getProperty("baseURL"));
        System.out.println("SSOFI: authStyle: "+config.getProperty("authStyle"));
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

}
