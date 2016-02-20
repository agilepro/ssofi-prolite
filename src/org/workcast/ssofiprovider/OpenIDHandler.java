/*
 * OpenIDHandler.java
 */
package org.workcast.ssofiprovider;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.Writer;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.openid4java.message.AuthFailure;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.DirectError;
import org.openid4java.message.Message;
import org.openid4java.message.MessageExtension;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.message.ax.FetchResponse;
import org.openid4java.server.ServerManager;
import org.workcast.json.JSONArray;
import org.workcast.json.JSONObject;
import org.workcast.json.JSONTokener;
import org.workcast.streams.HTMLWriter;
import org.workcast.streams.SSLPatch;

/**
 * Implements an OpenID provider
 *
 * Note there are two (2) users potentially on every request. Those can be
 * different. A user "joe" might display info of user "Larry".
 *
 * One is the "displayUser" which is the user information being displayed.
 * displayUser might be a null string value if the base address is accessed. The
 * display user is determined by the web address being accessed.
 *
 * The other is the "loggedUser" which is the user logged in. loggedUser might
 * be null if nobody is logged in. The logged in user is based on a cookie that
 * is set upon successful login. Note that the openId protocol does not require
 * that the display user be the user logging in.
 */
public class OpenIDHandler implements TemplateTokenRetriever {

    public static ServerManager manager = null;
    public static boolean initialized = false;
    public static Exception initFailure = null;

    // reconfigurable base address of the application (for proxy cases)
    public static String baseURL;

    //this is the last half of unique key for users, set every server start
    //this arbitrary value is based on the server mac address
    public static String guidTail;

    // this is internal address of the root of application (on this server)
    // use this for decomposing request URLs
    public static String rootURL;
    public static String knownAssetPath;

    private static AuthStyle authStyle = null;
    private static SessionHandler sHand = null;
    private static EmailHandler emailHandler = null;
    private static SecurityHandler securityHandler = null;
    private static EmailTokenManager tokenManager = null;

    private static int sessionDurationSeconds = 2500000;   //30 days
    private static boolean isLDAPMode = false;
    private static String configFilePath = "Unknown path";
    
    
    
    //MEMBER VARIABLES

    HttpServletRequest request;
    HttpServletResponse response;
    HttpSession session;

    AuthSession aSession;
    boolean saveSession = false;
    boolean destroySession = false;

    private String paramGo = "";

    private String loggedOpenId;

    private boolean isDisplaying = false;

    // addressedUserId is the id of the user you are DISPLAYING
    // which may have nothing to do with the user who is logged in
    // Any logged in user, can display any other user.
    private String addressedUserId;

    // If the UI is DISPLAYING user info, then this
    // member will hold the information to display
    private UserInformation displayInfo = null;

    // OpenID has a parameter called the assoc_handle and it
    // must be passed as part of the protocol, but I don't
    // know what it represents.  (you can probably guess.)
    private String assoc_handle;

    // This is the user that is attempting to log in, which
    // might have been passed as part of the protocol to
    // request authentication, or it might come from the
    // cookies that remember who you logged in as last time.
    private AddressParser requestedIdentity = null;

    //if the operation was a POST, and if the contents is JSON
    //then the resulting parsed value will appear here
    private JSONObject postedObject = null;

    /**
     * Handler static variables must be set up before handling any request. This
     * matches the servlet initialization protocol.
     */
    public static void init(ServletConfig config) {

        ServletContext sc = config.getServletContext();

        try {
            //get the server id from the MAC address of this machine
            guidTail = generateServerId();

            // disable Java certificate validation in the SSL level
            // necessary so that bytes can be read reliably over SSL
            SSLPatch.disableSSLCertValidation();

            String webInfPath = sc.getRealPath("/WEB-INF");
            File configFile = new File(webInfPath, "config.txt");
            configFilePath = configFile.toString();
            if (!configFile.exists()) {
                throw new Exception(
                        "Server needs to be configured.  No configuration file found: ("
                                + configFilePath + ")");
            }

            FileInputStream fis = new FileInputStream(configFile);
            Properties tprop = new Properties();
            tprop.load(fis);
            fis.close();
            Properties configSettings = tprop;

            File bipfile = new File(webInfPath, "blockedIp.txt");
            if (!bipfile.exists()) {
                bipfile.createNewFile();
            }
            String blockedIpListFilePath = bipfile.getPath();

            String sessionDurationStr = configSettings.getProperty("sessionDurationSeconds");
            if (sessionDurationStr!=null) {
                int durVal = Integer.parseInt(sessionDurationStr);
                if (durVal>600) {
                    //it is not realistic to have a session duration shorter than 10 minutes
                    //so only set if we have a value greater than 600 seconds.
                    sessionDurationSeconds = durVal;
                }
            }

            String sessionPath = configSettings.getProperty("sessionFolder");
            
            if (sessionPath == null) {
                sHand = new SessionHandlerMemory();
            }
            else {
                File sessionFolder = new File(sessionPath);
                sHand = new SessionHandlerFile(sessionFolder, sessionDurationSeconds);
            }
            isLDAPMode = "LDAP".equalsIgnoreCase(configSettings.getProperty("authStyle"));

            if (isLDAPMode) {
                authStyle = new AuthStyleLDAP(configSettings);
            }
            else {
                // NOTE: local mode must be the DEFAULT if no setting is supplied
                authStyle = new AuthStyleLocal(sc, configSettings);
            }

            baseURL = getRequiredConfigProperty(configSettings, "baseURL").toLowerCase();

            if (!baseURL.endsWith("/")) {
                baseURL = baseURL + "/";
            }
            rootURL = getRequiredConfigProperty(configSettings, "rootURL").toLowerCase();

            if (!rootURL.endsWith("/")) {
                rootURL = rootURL + "/";
            }
            knownAssetPath = rootURL + "$/";

            String captchaPrivateKey = configSettings.getProperty("captchaPrivateKey");
            String captchaPublicKey = configSettings.getProperty("captchaPublicKey");
            securityHandler = new SecurityHandler(captchaPrivateKey, captchaPublicKey,
                    blockedIpListFilePath);

            File emailConfigFile = new File(webInfPath, "EmailNotification.properties");
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
                Properties emailConfigSettings = propEmail;
                emailHandler = new EmailHandler(sc, emailConfigSettings);
            }
            catch (Exception e) {
                throw new Exception("Unable to initialize from email config file ("+emailConfigFile+")",e);
            }
            
            File emailTokenFile = new File(webInfPath, "EmailTokens.json");
            tokenManager = new EmailTokenManager(emailTokenFile);

            manager = new ServerManager();


            // configure the OpenID Provider's endpoint URL
            String pattern = baseURL+"{id}";
            AddressParser.initialize(pattern);

            manager.setOPEndpointUrl(baseURL);


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

    private static String getRequiredConfigProperty(Properties configSettings, String key)
            throws Exception {
        String val = configSettings.getProperty(key);
        if (val == null) {
            throw new Exception("Must have a setting for '" + key
                    + "' in the configuration file ("+configFilePath+")");
        }
        return val;
    }

    /**
     * Create a new instance for every request then the member functions don't
     * need to pass these all over the place Use an instance ONLY ONCE
     */
    public OpenIDHandler(HttpServletRequest httpReq, HttpServletResponse resp) {
        request = httpReq;
        response = resp;
        session = request.getSession();
    }

    /**
     * an instance of this is created and called on a single thread
     */
    public void doGet() {
        try {
            String sessionId = getSSOFISessionId();

            if (sHand==null) {
                streamTemplate("configErrScreen");
                return;
            }
            aSession = sHand.getAuthSession(sessionId);
            if (aSession.presumedId == null ||  aSession.presumedId.length()==0) {
                //if the session does not have an assumed user id in it, then
                //get the last good ID from the cookie.
                aSession.presumedId = findCookieValue("SSOFIUser");
            }

            doGetWithSession();
            // doGetWithSession never throws an exception, which means that this
            // is being saved whether an error occurs or not! That is the right
            // thing because the session object holds the error message for the
            // next page
            if (destroySession) {
                sHand.deleteAuthSession(sessionId);
            }
            else if (saveSession) {
                sHand.saveAuthSession(sessionId, aSession);
            }
        }
        catch (Exception e) {
            try {
                System.out.println("SSOFI: !!! Error getting or saving session information !!!");
                e.printStackTrace(System.out);
            }
            catch (Exception eeeee) {
                //really nothing we can do with this.
            }
        }
    }

    /**
     * an instance of this is created and called on a single thread
     */
    public void doPost() {
        try {
            System.out.println("SSOFI POST: "+request.getRequestURI());

            String postType = request.getHeader("Content-Type");
            if (postType!=null && (postType.toLowerCase().startsWith("text/plain")
                    || postType.toLowerCase().startsWith("application/json"))) {
                //now get the posted value
                //believe it ot not, some idiot decided that application/json was a security
                //hazard, and browsers WILL NOT post content cross domains, even if you
                //say it is OK, in application/json.  But they allow text/plain.
                //So call it EITHER text/plain or application/json and then parse it.
                InputStream is = request.getInputStream();
                JSONTokener jt = new JSONTokener(is);
                postedObject = new JSONObject(jt);
                is.close();
            }

            //this does not throw anything, but only call if above successful
            doGet();
        }
        catch (Exception e) {
            System.out.println("SSOFI: !!! Unable to handle post: "+e);
            e.printStackTrace(System.out);
        }
    }

    /**
     * Handles the request with the assumption that the session object has been
     * fetched, and will be saved afterwards.
     */
    public void doGetWithSession() {

        // check and see if this is the very first access in an attempt stream
        // initialize this object if there is not one already
        try {

            if (!initialized) {
                streamTemplate("configErrScreen");
                return;
            }

            String requestURL = request.getRequestURL().toString();

            if (baseURL == null) {
                // if not set at initialization time, set it here on first request
                baseURL = request.getRequestURL().toString();
            }

            if (!requestURL.startsWith(rootURL)) {
                throw new Exception("sorry, request must start with (" + rootURL + "):  ("
                        + requestURL + ")");
            }

            if (requestURL.startsWith(knownAssetPath)) {
                serveUpAsset(requestURL.substring(knownAssetPath.length()));
                return;
            }

            // set up loggedUserId and loggedOpenId
            determineLoggedUser();

            addressedUserId = requestURL.substring(rootURL.length());
            assoc_handle = request.getParameter("openid.assoc_handle");

            if (addressedUserId.length() > 0) {
                displayInfo = authStyle.getOrCreateUser(addressedUserId);
                isDisplaying = true;
            }

            String mode = defParam("openid.mode", "display");
            System.out.println("SSOFI: " + request.getRequestURL().toString().trim()
                    + " mode=" + mode
                    + "  isDisplaying="+isDisplaying
                    + "  loggedIn="+aSession.loggedIn());


            if (requestedIdentity!=null) {
                System.out.println("SSOFI: requestedIdentity: "+requestedIdentity.getOpenId());
            }
            else {
                System.out.println("SSOFI: requestedIdentity is NULL");
            }

            if (mode.startsWith("api")) {
                // Want to avoid saving a session as a result of every API call.  The API call will never
                // add or remove a session, it is only used to verify existing sessions.  In general API
                // round trips should be fast ... only a few seconds ... so persistence is not an
                // issue.  The problem is API calls made from the server do not preserve cookies, and a
                // new session is started every access, causing a flood of sessions, each potentially
                // lasting for a long time (a month) so persisting these sessions would be a waste.
                saveSession = false;
                APIHelper theApi = new APIHelper(aSession, postedObject, response, emailHandler, tokenManager);
                destroySession = theApi.handleAPICommand(mode);
                if (destroySession) {
                    //clear out any existing session id
                    createSSOFISessionId();
                }
                return;
            }

            // anything below here is LIKELY to change the session
            saveSession = true;

            if ("lookup".equals(mode)) {
                redirectToIdentityPage(authStyle.searchForID(reqParam("entered-id")));
            }
            else if ("loginView".equals(mode)) {
                // this is the mode that displays a login prompt
                modeLoginView();
            }
            else if ("changeIdView".equals(mode)) {
                // this is the mode that displays prompt to change id
                modeChangeIdView();
            }
            else if ("passwordView".equals(mode)) {
                // this is the mode that displays prompt to change password
                streamTemplate("changePassword");
            }
            else if ("register".equals(mode)) {
                // this is the mode that displays prompt to register new user
                // which then posts to 'registerNewAction'
                streamTemplate("userRegistration");
            }
            else if ("registerNewAction".equals(mode)) {
                modeRegisterNewAction();
            }
            else if ("confirmationKey".equals(mode)) {
                modeConfirmationKey();
            }
            else if ("validateKeyAction".equals(mode)) {
                modeValidateKeyAction();
            }
            else if ("registrationForm".equals(mode)) {
                // this is the mode that displays prompt for user details
                // which then posts to 'createNewUserAction'
                streamTemplate("registrationForm");
            }
            else if ("createNewUserAction".equals(mode)) {
                modeCreateNewUserAction();
            }
            else if ("login".equals(mode)) {
                // this takes the action of logging the user in, and returning
                // if all OK
                String enteredId = reqParam("entered-id");
                aSession.presumedId = enteredId;
                String password = reqParam("password");
                boolean flag = authStyle.authenticateUser(enteredId, password);
                if (flag) {
                    setLogin(enteredId);
                    //session.setMaxInactiveInterval(86000);  //about 1 day
                }
                else {
                    aSession.errMsg = new Exception("Unable to log you in to user id (" + enteredId
                            + ") with that password.  Please try again or reset your password.");
                }
                redirectToIdentityPage(defParam("display-id", ""));
            }
            else if ("loginAction".equals(mode)) {
                modeLoginAction();
            }
            else if ("cancelAction".equals(mode)) {
                returnLoginFailure();
            }
            else if ("passwordAction".equals(mode)) {
                modePasswordAction();
            }
            else if ("resetPasswordAction".equals(mode)) {
                modeResetPasswordAction();
            }
            else if ("acceptPreviousLogin".equals(mode)) {
                returnLoginSuccess();
            }
            else if ("relogin".equals(mode)) {
                setLogin(null);
                response.sendRedirect("?openid.mode=loginView");
            }
            else if ("quick".equals(mode)) {
                aSession.return_to = reqParam("go");
                aSession.quickLogin = true;
                if (aSession.loggedIn()) {
                    response.sendRedirect(aSession.return_to);
                }
                else {
                    response.sendRedirect("?openid.mode=loginView");
                }
            }
            else if ("logout".equals(mode)) {
                aSession.return_to = reqParam("go");
                aSession.quickLogin = true;
                destroySession = true;
                //set the cookie, but otherwise ignore the new sessionid
                createSSOFISessionId();
                setLogin(null);
                response.sendRedirect(aSession.return_to);
            }
            else if ("display".equals(mode)) {
                // just need to display the user information
                if (isDisplaying) {
                    displayUserPage();
                }
                else {
                    displayRootPage();
                }
            }
            else {
                aSession.quickLogin = false;
                modeOfficialOpenIDRequest(mode);
            }
        }
        catch (Exception e) {
            try {
                aSession.errMsg = e;
                System.out.println("SSOFI: error --- " + (new Date()).toString());
                e.printStackTrace(System.out);
                OutputStreamWriter errOut = new OutputStreamWriter(System.out);
                writeHtmlException(errOut, e);
                System.out.println("SSOFI: --- ------------------  --- ");
                response.sendRedirect(baseURL);
                return;

            }
            catch (Exception eeeee) {
                eeeee.printStackTrace();
            }
        }
    }

    /**
     * get the value directly from the current request object
     */
    String reqParam(String name) throws Exception {

        String val = request.getParameter(name);
        if (val == null || val.length() == 0) {
            throw new Exception("Got a request without a required '" + name + "' parameter");
        }
        return val;
    }

    /**
     * get the value directly from the current request object
     */
    String defParam(String name, String defaultVal) throws Exception {

        String val = request.getParameter(name);
        if (val == null || val.length() == 0) {
            return defaultVal;
        }
        return val;
    }

    /**
     * get the value from the original OpenID request
     */
    String getRequiredOpenIDParameter(String name) throws Exception {
        if (aSession.paramlist == null) {
            throw new Exception(
                    "Requesting a parameter when the paramter list has not be constructed yet.");
        }
        String ret = aSession.paramlist.getParameterValue(name);
        if (ret == null || ret.length() == 0) {
            throw new Exception("Got a request without a required '" + name + "' parameter");
        }
        return ret;
    }



    /**
     * Root page is the page that is displayed when no user is specified. This
     * is the place where you can enter a user id
     */
    private void displayRootPage() throws Exception {
        if (!aSession.loggedIn()) {
            streamTemplate("justAnonymous");
        }
        else {
            streamTemplate("justLoggedIn");
        }

    }

    private void displayUserPage() throws Exception {
        if (!aSession.loggedIn()) {
            streamTemplate("displayAnonymous");
        }
        else {
            streamTemplate("displayLoggedIn");
        }

    }

    private void modeLoginView() throws Exception {
        streamTemplate("promptedLogin");
        aSession.clearError();
    }

    private void modeChangeIdView() throws Exception {
        requestedIdentity = new AddressParser(aSession.presumedId);
        streamTemplate("promptedChangeId");
    }

    /**
     * this receives a post from a form with user profile detail infor it it
     * this will either create or update the user profile. It will save
     * regardless of whether there was a profile there before.
     */
    private void modeCreateNewUserAction() throws Exception {
        try {
            String option = reqParam("option");
            if (option.equals("Cancel")) {
                response.sendRedirect("?openid.mode=display");
                return;
            }
            if (!aSession.regEmailConfirmed) {
                throw new Exception(
                        "Illegal state!  Attempt to create a user profile when the email has not been confirmed.  Is this a hacker???");
            }

            String emailId = reqParam("emailId");
            String fullName = defParam("fullName", "");
            String pwd = reqParam("password");
            String confirmPwd = reqParam("confirmPwd");
            if (pwd.length() < 6) {
                throw new Exception("New password must be 6 or more characters long.");
            }
            if (!pwd.equals(confirmPwd)) {
                throw new Exception("The new password values supplied do not match.  Try again");
            }

            UserInformation userInfo = authStyle.getOrCreateUser(emailId);
            if (fullName != null && fullName.length()>0) {
                userInfo.fullName = fullName;
            }

            authStyle.updateUserInfo(userInfo, pwd);

            boolean loginFlag = authStyle.authenticateUser(emailId, pwd);
            if (loginFlag) {
                setLogin(emailId);
            }
            else {
                throw new Exception("Unable to log you in to user id (" + emailId
                        + ") with that password.  Please try again or reset your password.");
            }
            if ((aSession.return_to == null) || (aSession.return_to.length() <= 0)) {
                redirectToIdentityPage(defParam("display-id", ""));
            }
            else {
                returnLoginSuccess();
            }
            return;
        }
        catch (Exception e) {
            aSession.errMsg = e;
            response.sendRedirect("?openid.mode=registrationForm");
            return;
        }
    }

    /**
     * create the authentication response message with true == all authenticated
     * and OK
     */
    private void returnLoginSuccess() throws Exception {

        if (aSession.return_to != null) {
            response.sendRedirect(aSession.return_to);
            return;
        }

        // it could be that the user have been sitting there for a long time,
        // and the session has completely timed out. If so, handle gracefully as
        // possible by just redirecting to the root of the application.
        // It is also possible that this login was started by just accessing
        // the SSOFI, and there is no place to return to.
        if (aSession.paramlist == null) {
            aSession.errMsg = new Exception(
                    "If you started from an application, return to that application and start the login from there again.");
            response.sendRedirect(baseURL);
            return;
        }

        AuthRequest authReq = AuthRequest.createAuthRequest(aSession.paramlist,
                manager.getRealmVerifier());

        Message oidResp = manager.authResponse(authReq, loggedOpenId, loggedOpenId, true, false);
        if (oidResp instanceof DirectError) {
            ServletOutputStream os = response.getOutputStream();
            try {
                String respString = oidResp.keyValueFormEncoding();
                System.out.println("SSOFI: DirectError = " + respString);
                if (respString != null) {
                    os.write(respString.getBytes());
                }
            }
            finally {
                os.close();
            }
        }
        else if (oidResp instanceof AuthFailure) {
            System.out.println("SSOFI: AuthFailure = " + oidResp.keyValueFormEncoding());
            response.sendRedirect(oidResp.getDestinationUrl(true));
        }
        else {
            addAttributeValues(authReq, oidResp);
            manager.sign((AuthSuccess) oidResp);
            aSession.return_to = "";

            String destUrl = oidResp.getDestinationUrl(true);
            System.out.println("SSOFI: SUCCESS RETURN = " + destUrl);
            response.sendRedirect(destUrl);

        }

    }

    /**
     * Add extension to the response message if there is a request for
     * Attribute.
     */
    private void addAttributeValues(final AuthRequest authRequest, final Message oidResp)
            throws Exception {
        if (authRequest.hasExtension(AxMessage.OPENID_NS_AX)) {
            MessageExtension ext = authRequest.getExtension(AxMessage.OPENID_NS_AX);
            if (ext instanceof FetchRequest) {
                FetchRequest fetchReq = (FetchRequest) ext;
                @SuppressWarnings({ "unchecked", "unused" })
                Map<String, ?> required = fetchReq.getAttributes(true);
                @SuppressWarnings({ "unchecked", "unused" })
                Map<String, ?> optional = fetchReq.getAttributes(false);
                //the above can be used to determine what was asked for
                //but ignore it.  This server only returns email, first, last
                //and it always returns email, first, last


                //always put first name, last name, and email address in the properties
                UserInformation uinfo = authStyle.getOrCreateUser(aSession.loggedUserId());
                String fullName = uinfo.fullName;
                int spacePos = fullName.lastIndexOf(" ");
                String firstName = "";
                String lastName = fullName;
                if (spacePos>0) {
                    firstName = fullName.substring(0, spacePos);
                    lastName = fullName.substring(spacePos+1);
                }
                Map<String, String> userDataExt = new HashMap<String, String>();
                FetchResponse fetchResp = FetchResponse.createFetchResponse(fetchReq, userDataExt);
                fetchResp.addAttribute("Email", "http://schema.openid.net/contact/email", uinfo.emailAddress);
                fetchResp.addAttribute("FirstName", "http://schema.openid.net/namePerson/first", firstName);
                fetchResp.addAttribute("LastName", "http://schema.openid.net/namePerson/last", lastName);
                fetchResp.addAttribute("Guid", "http://schema.openid.net/person/guid", uinfo.key);
                oidResp.addExtension(fetchResp);
            }
        }
    }

    private void modePasswordAction() throws Exception {
        // this takes the action of logging the user in, and returning if all OK
        // first see if they pressed the Cancel key
        String op = reqParam("op");
        if (op.equals("Cancel")) {
            response.sendRedirect("?openid.mode=display");
            return;
        }
        String fullName = defParam("fullName", null);
        if (fullName!=null) {
            authStyle.changeFullName(aSession.loggedUserId(), fullName);
        }
        String oldPwd = defParam("oldPwd", null);
        if (oldPwd!=null) {
            String newPwd1 = reqParam("newPwd1");
            String newPwd2 = reqParam("newPwd2");
            boolean flag = authStyle.authenticateUser(aSession.loggedUserId(), oldPwd);
            if (!flag) {
                aSession.errMsg = new Exception(
                        "Doesn't look like you gave the correct old password.  Required in order to change passwords.");
                response.sendRedirect("?openid.mode=passwordView");
                return;
            }
            if (newPwd1.length() < 6) {
                aSession.errMsg = new Exception("New password must be 6 or more characters long.");
                response.sendRedirect("?openid.mode=passwordView");
                return;
            }
            if (!newPwd1.equals(newPwd2)) {
                aSession.errMsg = new Exception(
                        "The new password values supplied do not match.  Try again");
                response.sendRedirect("?openid.mode=passwordView");
                return;
            }

            authStyle.changePassword(aSession.loggedUserId(), oldPwd, newPwd1);
        }
        response.sendRedirect("?openid.mode=display");
    }

    private void modeResetPasswordAction() throws Exception {
        // this takes the action of logging the user in, and returning if all OK
        // first see if they pressed the Cancel key
        String op = reqParam("op");
        if (op.equals("Cancel")) {
            response.sendRedirect("?openid.mode=display");
            return;
        }
        String userId = reqParam("userId");
        String newPwd = reqParam("newPwd");

        if (newPwd.length() < 6) {
            throw new Exception("New password must be 6 or more characters long.");
        }

        authStyle.setPassword(userId, newPwd);
        response.sendRedirect("?openid.mode=display");
    }

    private void modeLoginAction() throws Exception {
        // this takes the action of logging the user in, and returning if all OK
        // first see if they pressed the Cancel key
        String enteredId = "";
        String password = "";

        String op = reqParam("op");
        if (op.equals("Cancel")) {
            returnLoginFailure();
            return;
        }
        enteredId = reqParam("entered-id");
        password = reqParam("password");
        if (authStyle.authenticateUser(enteredId, password)) {
            setLogin(enteredId);
            if (aSession.quickLogin) {
                //if you are not really doing the openid protocol, then you can get out quickly
                response.sendRedirect(aSession.return_to);
            }
            else {
                returnLoginSuccess();
            }
        }
        else {
            aSession.errMsg = new Exception("Unable to log you in to user id (" + enteredId
                + ") with that password.  Please try again or reset your password.");
            response.sendRedirect("?openid.mode=loginView");
        }
    }

    private void modeRegisterNewAction() throws Exception {
        String userId = reqParam("registerEmail");
        if (!emailHandler.validate(userId)) {
            aSession.errMsg = new Exception("The id supplied (" + userId
                    + ") does not appear to be a valid email address.");
            response.sendRedirect("?openid.mode=register");
            return;
        }

        // Security check
        aSession.saveParameterList(request);
        Properties secProp = new Properties();
        secProp.put(SecurityHandler.REGIS_REQ_REMOTE_IP, request.getRemoteAddr());
        secProp.put(SecurityHandler.REGIS_REQ_EMAILID, defParam("registerEmail", ""));
        secProp.put(SecurityHandler.CAPTCHA_CHALLANGE_REQ,
                defParam(SecurityHandler.CAPTCHA_CHALLANGE_REQ, ""));
        secProp.put(SecurityHandler.CAPTCHA_CHALLANGE_RESP,
                defParam(SecurityHandler.CAPTCHA_CHALLANGE_RESP, ""));

        try {
            securityHandler.validate(secProp);
        }
        catch (Exception e) {
            aSession.errMsg = e;
            response.sendRedirect("?openid.mode=register");
            return;
        }

        aSession.savedParams.clear();
        String magicNumber = tokenManager.generateEmailToken(userId);
        aSession.startRegistration(userId);
        emailHandler.sendVerifyEmail(userId, magicNumber, aSession.return_to);
        response.sendRedirect("?openid.mode=confirmationKey");
    }

    private void modeConfirmationKey() throws Exception {
        //if (aSession.regEmail==null) {
        //    aSession.errMsg = new Exception("Sorry, it has been too long and your session has been lost.");
        //    redirectToIdentityPage(defParam("display-id", ""));
        //    return;
        //}

        // this is the mode that displays prompt to change id
        // which then posts to 'validateKeyAction'
        displayInfo = authStyle.getOrCreateUser(aSession.regEmail);
        streamTemplate("enterConfirmationKey");
    }

    /*
     * The email contains this link:
     * 
     * {baseURL}?openid.mode=validateKeyAction
     *              &registerEmail={emailId}
     *              &registeredEmailKey={magicNumber}
     *              &app={application return URL}
     *              
     * so if you get both of those, and they match, then you have validated
     * a particular email address.  
     */
    private void modeValidateKeyAction() throws Exception {
        String registerEmail = reqParam("registerEmail");
        String confirmKey = reqParam("registeredEmailKey");
        aSession.return_to = defParam("app", aSession.return_to);

        UserInformation ui = authStyle.getOrCreateUser(registerEmail);
        
        if (aSession.loggedIn()) {
            if (aSession.loggedUserId().equals(registerEmail)) {
                //if user already logged in, as the correct person, 
                //check to see if the user password has been set
                //correctly.  If so, go ahead and redirect to the 
                //application as if it was a normal link.
                if (ui.hasPassword) {
                    response.sendRedirect(aSession.return_to);
                    return;
                }
        
                    
                
                //The only way they can get here, being logged in, but not having
                //a password, is if they got the password setting prompt, and 
                //then closed the window -- without losing their session.
                //Can anyone steal their session?
                //Can someone jump in an set their password before they had a chance?
                //good questions.   On the assumption this is not a real danger,
                //go ahead and prompt again to set the password, because they 
                //probably clicked on the link again, to try again to set password.
                aSession.presumedId = registerEmail;
                requestedIdentity = null;
                response.sendRedirect("?openid.mode=registrationForm");
                return;
            }
            
            //if logged in as a different user: what to do?   
            //Should this log-out and log-in again?  Invalidate the token?
            //Just redirect back to app would be convenient.
            //The problem with this is that if the user had been sent an invite
            //for a different email address, it is possible that the current
            //user does not have permission to access the app.  It might be
            //better to warn the user that they are proceeding as a different user.
            //On the other hand, if you are a user with redundant email addresses
            //you might just want to follow the link, and forget about the invite aspect.
            //The solution to this is to put both an invite and a non-invite link
            //in the email so that the user has the choice.
            throw new Exception("Sorry there is a problem.  You are logged in as "
                    +aSession.loggedUserId()
                    +" but you have clicked on a link validating the email for "
                    +registerEmail
                    +".  If you wish to validate that other email address, please logout before clicking on the link again.");
        }

        //we know they are not logged in here.  So check the token.  Set up as if this
        //person is really trying to log in.
        boolean valid = tokenManager.validateAndConsume(registerEmail, confirmKey);
        aSession.presumedId = registerEmail;
        requestedIdentity = null;

        if (!valid) {
            aSession.regEmail = registerEmail;
            aSession.errMsg = new Exception(
                    "If you have set up a password, please log in.  "
                    +"If not, request a new email registration email message.  "
                    +"The confirmation key supplied has expired. ");
            response.sendRedirect("?openid.mode=loginView");
            return;
        }

        if (valid) {
            //ok, they win the prize, this is a valid link, a valid match between the email address
            //and the magic number.  They have this email address.  We can NOW consider them logged in.
            //If they had been logged in as someone else, cancel that, and consider them logged in here
            aSession.regEmailConfirmed = true;
            aSession.regEmail = registerEmail;
            
            setLogin(registerEmail);

            //always go to register because they might have chose this link in order to reset their password
            response.sendRedirect("?openid.mode=registrationForm");
        }
    }

    private void modeOfficialOpenIDRequest(String mode) throws Exception {
        // here start the 'official OpenID' start requests, and so this
        // signifies the starting of a new request ... even if there is a
        // request in progress, this will override it.
        aSession.reinit(request);

        if ("checkid_setup".equals(mode)) {
            if (!aSession.loggedIn()) {
                response.sendRedirect("?openid.mode=loginView");
                return;
            }

            requestedIdentity = new AddressParser(aSession.presumedId);

            if (!aSession.presumedId.equals(loggedOpenId) && !requestedIdentity.isRoot()) {
                response.sendRedirect("?openid.mode=changeIdView");
                return;
            }

            returnLoginSuccess();
            return;
        }

        if ("checkid_immediate".equals(mode)) {
            if (!aSession.loggedIn()) {
                returnLoginFailure();
            }
            else {
                returnLoginSuccess();
            }
            return;
        }

        Message resMsg;
        String responseText;

        if ("associate".equals(mode)) {
            // --- process an association request ---
            resMsg = manager.associationResponse(aSession.paramlist);
            responseText = resMsg.keyValueFormEncoding();
        }
        else if ("check_authentication".equals(mode)) {
            // --- processing a verification request ---
            resMsg = manager.verify(aSession.paramlist);
            responseText = resMsg.keyValueFormEncoding();
        }
        else {
            throw new Exception("Unable to handle request for mode: " + mode);
        }

        // return the result to the user
        Writer out = response.getWriter();
        out.write(responseText);
        out.flush();
    }

    /**
     * create the authentication response message with false == not
     * authenticated
     */
    private void returnLoginFailure() throws Exception {

        // it could be that the user have been sitting there for a long time,
        // and the
        // session has completely timed out. If so, handle gracefully as
        // possible
        // by just redirecting to the root of the application.
        if (aSession.paramlist == null) {
            aSession.errMsg = new Exception(
                    "Session time out... too much time to login in and no longer have information about where to return to.");
            response.sendRedirect(baseURL);
            return;
        }

        Message resMsg = manager.authResponse(aSession.paramlist, aSession.presumedId,
                aSession.presumedId, false);

        String urlTail = resMsg.wwwFormEncoding();
        int questionPos = aSession.return_to.indexOf("?");
        String dest;
        if (questionPos < 0) {
            dest = aSession.return_to + "?" + urlTail;
        }
        else {
            dest = aSession.return_to + "&" + urlTail;
        }
        System.out.println("SSOFI: FAILURE RETURN = " + dest);
        response.sendRedirect(dest);
    }

    private void redirectToIdentityPage(String gotoId) throws Exception {
        if (gotoId == null) {
            gotoId = "";
        }
        String dest = baseURL + gotoId;
        response.sendRedirect(dest);
    }

    /**
     * Set to null to clear the login
     */
    private void setLogin(String loggedId) throws Exception {
        if (loggedId == null) {
            aSession.logout();
            loggedOpenId = "";
        }
        else {
            UserInformation ui = authStyle.getOrCreateUser(loggedId);
            aSession.login(loggedId, ui.fullName);
            loggedOpenId = AddressParser.composeOpenId(loggedId);

            // This is a 'low security' cookie.  It keeps the Id of the usr
            // that successfully logged in so that next time we can
            // remember and save the user having to type in again.
            // But there is no security value here.
            Cookie userIdCookie = new Cookie("SSOFIUser", loggedId);
            userIdCookie.setMaxAge(31000000); // about 1 year
            userIdCookie.setPath("/"); // everything on the server
            response.addCookie(userIdCookie);
        }
    }

    
    public String getBestGuessId() {
        if (aSession.loggedIn()) {
            return aSession.loggedUserId();
        }
        else if (aSession.presumedId!=null && aSession.presumedId.length()>0){
            return aSession.presumedId;
        }
        else {
            return findCookieValue("SSOFIUser");
        }
    }

    
    /**
     * returns null if not logged in checks the session. If no session, it
     * checks the cookies. if no cookies, or cookies invalid, then not logged
     * in.
     */
    private void determineLoggedUser() throws Exception {
        if (aSession.loggedIn()) {
            loggedOpenId = AddressParser.composeOpenId(aSession.loggedUserId());
        }
        else {
            loggedOpenId = "";
        }
    }

    public void serveUpAsset(String resourceName) throws Exception {
        ServletContext sc = session.getServletContext();
        String path = sc.getRealPath("/$/" + resourceName);

        TemplateStreamer.streamRawFile(response.getOutputStream(), new File(path));
    }

    private void streamTemplate(String fileName) throws Exception {
        javax.servlet.ServletContext sc2 = session.getServletContext();
        File ctxPath = new File(sc2.getRealPath("/"));

        // fist check to see if a special auth style specific version exists
        if (authStyle != null) {
            String testName = fileName + "." + authStyle.getStyleIndicator() + ".htm";
            File templateFile = new File(ctxPath, testName);
            if (templateFile.exists()) {
                streamTemplateCore(templateFile);
                return;
            }
        }

        // if not, use the generic one
        String testName2 = fileName + ".htm";
        File templateFile2 = new File(ctxPath, testName2);
        if (templateFile2.exists()) {
            streamTemplateCore(templateFile2);
            return;
        }
        throw new Exception("Can't find the template file: " + templateFile2.toString());
    }

    private void streamTemplateCore(File templateFile) throws Exception {
        try {
            response.setContentType("text/html;charset=UTF-8");
            Writer out = response.getWriter();
            InputStream is = new FileInputStream(templateFile);
            Reader isr = new InputStreamReader(is, "UTF-8");
            TemplateStreamer.streamTemplate(out, isr, this);
            isr.close();
            out.flush();

            // clear out any recorded error now that it has been displayed
            if (aSession!=null) {
                aSession.clearError();
            }
        }
        catch (Exception e) {
            throw new Exception("Error streaming template file (" + templateFile.toString() + ").",
                    e);
        }
    }

    /**
     * Given a named token, write out the corresponding value
     */
    public void writeTokenValue(Writer out, String tokenName) throws Exception {
        try {
            if ("userInfo".equals(tokenName)) {
                JSONObject jo = new JSONObject();
                jo.put("isLDAP", isLDAPMode);
                jo.put("isLocal", !isLDAPMode);
                if (aSession.loggedIn()) {
                    jo.put("userId", aSession.loggedUserId());
                    jo.put("userEmail", aSession.regEmail);
                    UserInformation userInfo = authStyle.getOrCreateUser(aSession.loggedUserId());
                    if (userInfo.exists) {
                        jo.put("userName", userInfo.fullName);
                    }
                    jo.put("openId", loggedOpenId);
                }
                if (displayInfo != null && displayInfo.exists) {
                    jo.put("dispId", displayInfo.key);
                    jo.put("dispName", displayInfo.fullName);
                    jo.put("dispEmail", displayInfo.emailAddress);
                }
                jo.put("expectedUser", getBestGuessId());
                
                String errStr = "";
                JSONArray errors = new JSONArray();
                Throwable runner = aSession.errMsg;
                while (runner!=null) {
                    String msg = runner.toString();
                    //strip off the class name if there is one
                    if (msg.startsWith("java.lang.Exception")
                            || msg.startsWith("java.lang.RuntimeException")) {
                        int pos = msg.indexOf(":");
                        msg = msg.substring(pos+2);
                    }
                    int pos = msg.indexOf("nested exception");
                    if (pos>3) {
                        //some exceptions unnecessarily duplicate the cause exception,
                        //since we don't need it, strip it out.
                        msg = msg.substring(0, pos-3);
                    }
                    errors.put(msg);
                    errStr = errStr + msg + "\n ";
                    runner = runner.getCause();
                }
                jo.put("userError", errStr);
                jo.put("errors", errors);
                jo.put("baseUrl", baseURL);
                jo.put("go", paramGo);
                jo.write(out,2,12);
            }
            else if ("thisPage".equals(tokenName)) {
                HTMLWriter.writeHtml(out, baseURL);
            }
            else if ("fullName".equals(tokenName)) {
                if (displayInfo != null && displayInfo.exists) {
                    HTMLWriter.writeHtml(out, displayInfo.fullName);
                }
            }
            else if ("emailAddress".equals(tokenName)) {
                if (displayInfo != null && displayInfo.exists) {
                    HTMLWriter.writeHtml(out, displayInfo.emailAddress);
                }
            }
            else if ("id".equals(tokenName)) {
                if (displayInfo != null && displayInfo.exists) {
                    HTMLWriter.writeHtml(out, displayInfo.key);
                }
            }
            else if ("loggedUserId".equals(tokenName)) {
                if (aSession.loggedIn()) {
                    HTMLWriter.writeHtml(out, aSession.loggedUserId());
                }
            }
            else if ("loggedName".equals(tokenName)) {
                if (aSession.loggedIn()) {
                    UserInformation userInfo = authStyle.getOrCreateUser(aSession.loggedUserId());
                    if (userInfo.exists) {
                        HTMLWriter.writeHtml(out, userInfo.fullName);
                    }
                }
            }
            else if ("loggedKey".equals(tokenName)) {
                if (aSession.loggedIn()) {
                    UserInformation userInfo = authStyle.getOrCreateUser(aSession.loggedUserId());
                    if (userInfo.exists) {
                        HTMLWriter.writeHtml(out, userInfo.key);
                    }
                }
            }
            else if ("loggedOpenId".equals(tokenName)) {
                HTMLWriter.writeHtml(out, loggedOpenId);
            }
            else if ("reqUserId".equals(tokenName)) {
                if (requestedIdentity != null) {
                    System.out.append("SSOFI: displaying requested id: "+requestedIdentity.getUserId());
                    HTMLWriter.writeHtml(out, requestedIdentity.getUserId());
                }
                else {
                    HTMLWriter.writeHtml(out, aSession.presumedId);
                }
            }
            else if ("reqOpenId".equals(tokenName)) {
                if (requestedIdentity != null) {
                    HTMLWriter.writeHtml(out, requestedIdentity.getOpenId());
                }
            }
            else if ("addrOpenId".equals(tokenName)) {
                if (addressedUserId != null) {
                    HTMLWriter.writeHtml(out, addressedUserId);
                }
            }
            else if ("addrId".equals(tokenName)) {
                if (addressedUserId != null) {
                    HTMLWriter.writeHtml(out, addressedUserId);
                }
            }
            else if ("registeredEmailId".equals(tokenName)) {
                if (aSession != null) {
                    HTMLWriter.writeHtml(out, aSession.regEmail);
                }
            }
            else if ("root".equals(tokenName)) {
                HTMLWriter.writeHtml(out, baseURL);
            }
            else if ("Note".equals(tokenName)) {
                String note = "";
                if (isLDAPMode) {
                    note = "The user name and password that you "
                            + "enter above will be checked against a "
                            + "directory server using LDAP protocol.";
                }
                else {
                    note = "Enter your email address and password. "
                            + "If you have never set up a password for your email address then use \"Register Here\" link for a new value "
                            + ", or if you have forgotten your password, you should use the \"Forgot Your Password\" link "
                            + "to reset your password.";
                }
                HTMLWriter.writeHtml(out, note);
            }
            else if ("go".equals(tokenName)) {
                HTMLWriter.writeHtml(out, paramGo);
            }
            else if ("return_to".equals(tokenName)) {

                HTMLWriter.writeHtml(out, aSession.return_to);
            }
            else if ("assoc_handle".equals(tokenName)) {

                HTMLWriter.writeHtml(out, assoc_handle);
            }
            else if ("serverError".equals(tokenName)) {
                writeHtmlException(out, initFailure);
            }
            else if ("userError".equals(tokenName)) {
                writeHtmlException(out, aSession.errMsg);
            }
            else if ("captcha".equals(tokenName)) {
                String cerr = null;
                if (aSession.errMsg != null) {
                    cerr = aSession.errMsg.getMessage();
                }
                out.write(securityHandler.getCaptchaHtML(cerr));
            }
            else {
                //if we don't know what it means, write it back out, because
                //it might be a AngularJS token which needs to be transmitted.
                HTMLWriter.writeHtml(out, "{{" + tokenName + "}}");
            }
        }
        catch (Exception e) {
            throw new Exception("Unable to supply value for token: "+tokenName, e);
        }
    }

    private void writeHtmlException(Writer out, Exception anException) throws Exception {
        if (anException == null) {
            return; // nothing to write
        }
        Throwable t = anException;
        boolean needBreak = false;
        while (t != null) {
            String msg = t.toString();
            if (msg.startsWith("java.lang.Exception")) {
                msg = msg.substring(21);
            }
            if (needBreak) {
                out.write("<br/> \n ");
            }
            HTMLWriter.writeHtml(out, msg);
            t = t.getCause();
            needBreak = true;
        }

        out.write("\n<!--");
        anException.printStackTrace(new PrintWriter(out));
        out.write("\n-->");
    }

    // quite simply: add space characters before and after every slash so that
    // URL wraps nicely. Only when URL used for display.
    public void writeFriendlyURL(Writer out, String urlValue) throws Exception {
        // ignore null values
        if (urlValue == null) {
            return;
        }
        int startPos = 0;
        int slashPos = urlValue.indexOf("/");
        while (slashPos >= 0) {

            HTMLWriter.writeHtml(out, urlValue.substring(startPos, slashPos));
            out.write(" / ");
            startPos = slashPos + 1;
            slashPos = urlValue.indexOf("/", startPos);
        }
        HTMLWriter.writeHtml(out, urlValue.substring(startPos));
    }

    public String getSSOFISessionId() {
        String sessionId = findCookieValue("SSOFISession");
        if (sessionId == null || sessionId.length() < 10) {
            return createSSOFISessionId();
        }


        System.out.println("SSOFI: found existing session cookie: "+sessionId);

        //TODO: determine if it is right to refresh the time period
        //of this session in the cookie.  Perhaps this time should
        //be set only when the session is created
        Cookie previousId = new Cookie("SSOFISession", sessionId);
        previousId.setMaxAge(sessionDurationSeconds);
        previousId.setPath("/"); // everything on the server
        response.addCookie(previousId);
        return sessionId;
    }

    /**
     * Generate a new, different session ID.
     * This should be called immediately after logout so that on the next
     * request the browser is using a new session.
     * The previous session object should be destroyed as well.
     */
    public String createSSOFISessionId() {
        String sessionId = "S" + IdGenerator.createMagicNumber();
        System.out.println("SSOFI: NEW session id generated: "+sessionId);

        Cookie previousId = new Cookie("SSOFISession", sessionId);
        previousId.setMaxAge(sessionDurationSeconds);
        previousId.setPath("/"); // everything on the server
        response.addCookie(previousId);
        return sessionId;
    }


    public String findCookieValue(String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie oneCookie : cookies) {
                if (oneCookie != null) {
                    String cName = oneCookie.getName();
                    if (cName != null && cookieName.equals(cName)) {
                        return oneCookie.getValue();
                    }
                }
            }
        }
        return null;
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
        if (mac==null) {
            throw new Exception("The method 'getHArdwareAddress' was not able to return an actual mac address.  Something is wrong with network configuration");
        }
        long macValue = 0;
        for (byte oneByte : mac) {
            macValue = (macValue<<8) + (oneByte+256)%256;
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
