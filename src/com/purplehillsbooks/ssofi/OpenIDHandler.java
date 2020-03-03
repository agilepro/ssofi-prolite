/*
 * OpenIDHandler.java
 */
package com.purplehillsbooks.ssofi;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.Writer;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Properties;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.http.Cookie;
import com.purplehillsbooks.json.JSONArray;
import com.purplehillsbooks.json.JSONException;
import com.purplehillsbooks.json.JSONObject;
import com.purplehillsbooks.json.JSONTokener;
import com.purplehillsbooks.streams.HTMLWriter;
import com.purplehillsbooks.temps.TemplateStreamer;
import com.purplehillsbooks.temps.TemplateTokenRetriever;

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

    private static SSOFI ssofi;


    //MEMBER VARIABLES
    WebRequest wr;

    private boolean isPost = false;

    AuthSession aSession;
    boolean saveSession = false;
    boolean destroySession = false;

    private String paramGo = "";

    private String loggedOpenId;

    // addressedUserId is the id of the user you are DISPLAYING
    // which may have nothing to do with the user who is logged in
    // Any logged in user, can display any other user.
    private String addressedUserId;

    // If the UI is DISPLAYING user info, then this
    // member will hold the information to display
    private UserInformation displayInfo = null;

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

        ssofi = SSOFI.getSSOFI(sc);

    }

    /**
     * Create a new instance for every request then the member functions don't
     * need to pass these all over the place Use an instance ONLY ONCE
     */
    public OpenIDHandler(WebRequest _wr) throws Exception {
        wr = _wr;
    }

    /**
     * an instance of this is created and called on a single thread
     */
    public void doGet() {
        String sessionId = "?";
        try {
            sessionId = ssofi.getSSOFISessionId(wr);

            if (ssofi.sHand==null) {
                streamTemplate("configErrScreen");
                return;
            }
            aSession = ssofi.sHand.getAuthSession(wr, sessionId);

            doGetWithSession();
            // doGetWithSession never throws an exception, which means that this
            // is being saved whether an error occurs or not! That is the right
            // thing because the session object holds the error message for the
            // next page
            if (destroySession) {
                ssofi.sHand.deleteAuthSession(sessionId);
            }
            else if (saveSession) {
                ssofi.sHand.saveAuthSession(sessionId, aSession);
            }
        }
        catch (Exception e) {
            //this exception is not from the operational logic, but the preparation
            //logic or finalization logic which does not deserve sending results
            System.out.println("SSOFI: !!! Error getting or saving session information !!!");
            JSONException.traceException(e, "GET: session: "+sessionId);
        }
    }

    /**
     * an instance of this is created and called on a single thread
     */
    public void doPost() {
        try {
            isPost = true;
            String postType = wr.request.getHeader("Content-Type");
            if (postType!=null && (postType.toLowerCase().startsWith("text/plain")
                    || postType.toLowerCase().startsWith("application/json"))) {
                //now get the posted value
                //believe it ot not, some idiot decided that application/json was a security
                //hazard, and browsers WILL NOT post content cross domains, even if you
                //say it is OK, in application/json.  But they allow text/plain.
                //So call it EITHER text/plain or application/json and then parse it.
                InputStream is = wr.request.getInputStream();
                JSONTokener jt = new JSONTokener(is);
                postedObject = new JSONObject(jt);
                is.close();
            }
            else {
                throw new Exception("SSOFI: doPost but can not understand Content-Type: "+postType);
            }

            //this does not throw anything, but only call if above successful
            doGet();
        }
        catch (Exception e) {
            System.out.println("SSOFI: !!! Unable to handle post to: "+wr.requestURL);
            JSONException.traceException(e, "POST");
        }
    }

    private void assertPost(String mode) throws Exception {
        if (!isPost) {
            throw new JSONException("Program-Logic-Error: The request for mode ({0}) must be a POST request.", mode);
        }
    }
    private void assertGet(String mode) throws Exception {
        if (isPost) {
            throw new JSONException("Program-Logic-Error: The request for mode ({0}) must be a GET request.", mode);
        }
    }
    private void assertLoggedIn(String mode) throws Exception {
        if (!aSession.loggedIn()) {
            throw new JSONException("Program-Logic-Error: The request for mode ({0}) must be a accessed only when logged in.  Did you logout in a different browser tab?", mode);
        }
    }
    private void assertAnonymous(String mode) throws Exception {
        if (aSession.loggedIn()) {
            throw new JSONException("Program-Logic-Error: The request for mode ({0}) must be accessed when NOT logged in.  Did you log in recently in another browser tab?", mode);
        }
    }

    /**
     * Handles the request with the assumption that the session object has been
     * fetched, and will be saved afterwards.
     */
    public void doGetWithSession() {
        String requestURL = "";

        // check and see if this is the very first access in an attempt stream
        // initialize this object if there is not one already
        try {

            if (!ssofi.initialized) {
                streamTemplate("configErrScreen");
                return;
            }

            requestURL = wr.requestURL;
            wr.response.setContentType("text/html; charset=utf-8");

            if (!requestURL.startsWith(ssofi.rootURL)) {
                throw new JSONException("sorry, request must start with ({0}):  ({1})", ssofi.rootURL, requestURL);
            }

            if (requestURL.startsWith(ssofi.knownAssetPath)) {
                serveUpAsset(requestURL.substring(ssofi.knownAssetPath.length()));
                return;
            }


            // set up loggedUserId and loggedOpenId
            determineLoggedUser();

            addressedUserId = requestURL.substring(ssofi.rootURL.length());

            if (addressedUserId.length() > 0) {
                displayInfo = ssofi.authStyle.getOrCreateUser(addressedUserId);
            }

            String mode = defParam("openid.mode", "displayForm");
            String loginIndicator = " (anonymous) ";
            if (aSession.loggedIn()) {
                loginIndicator =    " (logged in) ";
            }
            System.out.println("SSOFI REQUEST: "+mode+loginIndicator+requestURL);

            if (mode.startsWith("api")) {
                // Want to avoid saving a session as a result of every API call.  The API call will never
                // add or remove a session, it is only used to verify existing sessions.  In general API
                // round trips should be fast ... only a few seconds ... so persistence is not an
                // issue.  The problem is API calls made from the server do not preserve cookies, and a
                // new session is started every access, causing a flood of sessions, each potentially
                // lasting for a long time (a month) so persisting these sessions would be a waste.
                saveSession = false;
                APIHelper theApi = new APIHelper(aSession, postedObject, wr, ssofi.emailHandler, ssofi.tokenManager);
                destroySession = theApi.handleAPICommand(mode);
                if (destroySession) {
                    //clear out any existing session id
                    ssofi.createSSOFISessionId(wr);
                }
                return;
            }

            // anything below here is LIKELY to change the session
            saveSession = true;

            if ("quick".equals(mode)) {
                if (aSession.loggedIn()) {
                    //user is logged in, so just jump back
                    //we don't care if logged in as a different user.
                    //preserve the current logged in user session
                    wr.response.sendRedirect(reqParam("go"));
                }
                else {
                    aSession.return_to = reqParam("go");
                    aSession.quickLogin = true;
                    wr.response.sendRedirect("?openid.mode=displayForm");
                }
            }
            else if ("logout".equals(mode)) {
                aSession.return_to = reqParam("go");
                aSession.quickLogin = true;
                destroySession = true;
                //set the cookie, but otherwise ignore the new sessionid
                ssofi.createSSOFISessionId(wr);
                setLogin(null);
                wr.response.sendRedirect(aSession.return_to);
            }
            else if ("loginAction".equals(mode)) {
                assertPost(mode);
                //if already logged in, then this is a NOOP
                modeLoginAction();
            }
            else if ("passwordForm".equals(mode)) {
                assertGet(mode);
                assertLoggedIn(mode);
                // this is the mode that displays prompt to change password
                streamTemplate("passwordForm");
            }
            else if ("passwordAction".equals(mode)) {
                assertPost(mode);
                assertLoggedIn(mode);
                modePasswordAction();
            }
            else if ("requestForm".equals(mode)) {
                assertGet(mode);
                assertAnonymous(mode);
                // this is the mode that displays prompt to register new user
                // which then posts to 'registerNewAction'
                setRequestedId();
                streamTemplate("requestForm");
            }
            else if ("registerNewAction".equals(mode)) {
                assertPost(mode);
                assertAnonymous(mode);
                modeRegisterNewAction();
            }
            else if ("confirmForm".equals(mode)) {
                assertGet(mode);
                assertAnonymous(mode);
                // displays prompt to enter verification key
                // which then posts to 'validateKeyAction'
                setRequestedId();
                displayInfo = ssofi.authStyle.getOrCreateUser(aSession.regEmail);
                streamTemplate("confirmForm");
            }
            else if ("validateKeyAction".equals(mode)) {
                //this can be GET or POST, and can be done while logged in or not
                //this will log you in if all is proper
                modeValidateKeyAction();
            }
            else if ("registerForm".equals(mode)) {
                assertGet(mode);
                assertLoggedIn(mode);
               // this is the mode that displays prompt for user details
                // which then posts to 'createNewUserAction'
                streamTemplate("registerForm");
            }
            else if ("createNewUserAction".equals(mode)) {
                assertPost(mode);
                assertLoggedIn(mode);
                modeCreateNewUserAction();
            }
            else if ("login".equals(mode)) {
                // this takes the action of logging the user in, and returning
                // if all OK
                String enteredId = reqParam("entered-id");
                aSession.presumedId = enteredId;
                String password = reqParam("password");
                boolean flag = ssofi.authStyle.authenticateUser(enteredId, password);
                if (flag) {
                    setLogin(enteredId);
                }
                else {
                    aSession.saveError(new JSONException("Unable to log you in to user id ({0}) with that password.  Please try again or reset your password.", enteredId));
                }
                wr.response.sendRedirect(ssofi.baseURL);
            }
            else {
                if (!"loginView".equals(mode) && !"displayForm".equals(mode)) {
                    throw new JSONException("Don't understand the mode ({0})", mode);
                }
                assertGet(mode);
                // login or display or display any kind of error
                displayRootPage();
            }
        }
        catch (Exception eorig) {
            try {
                Exception e = new Exception("Unable to handle request: "+requestURL, eorig);
                aSession.saveError(e);
                System.out.println("SSOFI: error --- " + AuthSession.currentTimeString());
                JSONException.traceException(e, "OpenIDHandler");
                System.out.println("SSOFI: --- ------------------  --- ");
                displayErrorPage(eorig);
                return;
            }
            catch (Exception eeeee) {
                JSONException.traceException(eeeee, "EXCEPTION during EXCEPTION - doGetWithSession");
            }
        }
    }


    private void setRequestedId() throws Exception  {
        String email = wr.request.getParameter("email");
        if (email!=null) {
            requestedIdentity = new AddressParser(ssofi.baseURL + email);
        }
    }

    /**
     * get the value directly from the current request object
     */
    String reqParam(String name) throws Exception {

        String val = wr.request.getParameter(name);
        if (val == null || val.length() == 0) {
            throw new JSONException("Got a request without a required '{0}' parameter", name);
        }
        return val;
    }

    /**
     * get the value directly from the current request object
     */
    String defParam(String name, String defaultVal) throws Exception {

        String val = wr.request.getParameter(name);
        if (val == null || val.length() == 0) {
            return defaultVal;
        }
        return val;
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

    private void displayErrorPage(Exception e) {
        wr.response.setContentType("text/html;charset=UTF-8");

        //Why are we telling IE how to behave?  Because IE can be set into a mode that causes it to
        //run emulation of IE7, even though it is a much more recent browser.  It ignores the fact that
        //it is more recent, and emulates the old browser unnecessarily.  This appears to be an administration
        //option that allow an organization to run all IE as if they were an older IE.
        //This command says to act like IE 10.  Would be better if we could say IE10 and above.
        //Not all versions of IE obey this command.  Microsoft say that the best practice is to put
        //this in a header, and not a meta-tag because a metatag will slow down handling of the page becausei
        //it has to start parsing all over again.  We don't really want 10, but there seems no setting for
        //IE11 and I am worried that older browsers wont know what Edge is.
        wr.response.setHeader("X-UA-Compatible", "IE=EmulateIE10");

        try {
            Writer out = wr.w;
            out.write("<html><body>\n<h1>Error Occurred</h1>\n<pre>");
            JSONObject errObj = JSONException.convertToJSON(e, "Accessing SSOFI main capabilities");
            errObj.write(out, 2, 2);
            out.write("</pre>\n</body></html>");
            out.flush();
        }
        catch( Exception e2) {
            JSONException.traceException(e2, "FAILURE creating error page");
        }

        // clear out any recorded error now that it has been displayed
        if (aSession!=null) {
            aSession.clearError();
        }
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
                wr.response.sendRedirect("?openid.mode=displayForm");
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

            UserInformation userInfo = ssofi.authStyle.getOrCreateUser(emailId);
            if (fullName != null && fullName.length()>0) {
                userInfo.fullName = fullName;
            }

            ssofi.authStyle.updateUserInfo(userInfo, pwd);

            boolean loginFlag = ssofi.authStyle.authenticateUser(emailId, pwd);
            if (loginFlag) {
                setLogin(emailId);
            }
            else {
                throw new JSONException("Unable to log you in to user id ({0}) with that password.  Please try again or reset your password.", emailId);
            }
            if ((aSession.return_to != null) && (aSession.return_to.length() > 0)) {
                wr.response.sendRedirect(aSession.return_to);
            }
            else {
                wr.response.sendRedirect(ssofi.baseURL);
            }
            return;
        }
        catch (Exception e) {
            aSession.saveError(e);
            wr.response.sendRedirect("?openid.mode=registerForm");
            return;
        }
    }



    private void modePasswordAction() throws Exception {
        // this takes the action of logging the user in, and returning if all OK
        // first see if they pressed the Cancel key
        String op = reqParam("op");
        if (op.equals("Cancel")) {
            wr.response.sendRedirect("?openid.mode=displayForm");
            return;
        }
        String fullName = defParam("fullName", null);
        if (fullName!=null) {
            ssofi.authStyle.changeFullName(aSession.loggedUserId(), fullName);
        }
        String oldPwd = defParam("oldPwd", null);
        if (oldPwd!=null) {
            String newPwd1 = reqParam("newPwd1");
            String newPwd2 = reqParam("newPwd2");
            boolean flag = ssofi.authStyle.authenticateUser(aSession.loggedUserId(), oldPwd);
            if (!flag) {
                aSession.saveError(new Exception(
                        "Doesn't look like you gave the correct old password.  Required in order to change passwords."));
                wr.response.sendRedirect("?openid.mode=passwordForm");
                return;
            }
            if (newPwd1.length() < 6) {
                aSession.saveError(new Exception("New password must be 6 or more characters long."));
                wr.response.sendRedirect("?openid.mode=passwordForm");
                return;
            }
            if (!newPwd1.equals(newPwd2)) {
                aSession.saveError(new Exception(
                        "The new password values supplied do not match.  Try again"));
                wr.response.sendRedirect("?openid.mode=passwordForm");
                return;
            }

            ssofi.authStyle.changePassword(aSession.loggedUserId(), oldPwd, newPwd1);
        }
        wr.response.sendRedirect("?openid.mode=displayForm");
    }



    private void modeLoginAction() throws Exception {
        // this takes the action of logging the user in, and returning if all OK
        // first see if they pressed the Cancel key
        String enteredId = "";
        String password = "";

        enteredId = reqParam("entered-id");
        password = reqParam("password");
        if (ssofi.authStyle.authenticateUser(enteredId, password)) {
            setLogin(enteredId);
            if (aSession.quickLogin) {
                //if you are not really doing the openid protocol, then you can get out quickly
                wr.response.sendRedirect(aSession.return_to);
            }
            else {
                wr.response.sendRedirect("?openid.mode=displayForm");
            }
        }
        else {
            throw new Exception("Unable to log you in to user id (" + enteredId
                + ") with that password.  Please try again or reset your password.");
        }
    }

    private void modeRegisterNewAction() throws Exception {
        String userId = reqParam("registerEmail").trim();
        if (!ssofi.emailHandler.validate(userId)) {
            aSession.saveError(new Exception("The id supplied (" + userId
                    + ") does not appear to be a valid email address."));
            wr.response.sendRedirect("?openid.mode=requestForm&email="+URLEncoder.encode(userId, "UTF-8"));
            return;
        }

        // Security check
        aSession.saveParameterList(wr.request);
        Properties secProp = new Properties();
        secProp.put(SecurityHandler.REGIS_REQ_REMOTE_IP, wr.request.getRemoteAddr());
        secProp.put(SecurityHandler.REGIS_REQ_EMAILID, defParam("registerEmail", ""));
        secProp.put(SecurityHandler.CAPTCHA_CHALLANGE_REQ,
                defParam(SecurityHandler.CAPTCHA_CHALLANGE_REQ, ""));
        secProp.put(SecurityHandler.CAPTCHA_CHALLANGE_RESP,
                defParam(SecurityHandler.CAPTCHA_CHALLANGE_RESP, ""));

        try {
            ssofi.securityHandler.validate(secProp);
        }
        catch (Exception e) {
            aSession.saveError(e);
            wr.response.sendRedirect("?openid.mode=requestForm&email="+URLEncoder.encode(userId, "UTF-8"));
            return;
        }

        aSession.presumedId = userId;

        aSession.savedParams.clear();
        String magicNumber = ssofi.tokenManager.generateEmailToken(userId);
        aSession.startRegistration(userId);
        ssofi.emailHandler.sendVerifyEmail(userId, magicNumber, aSession.return_to, ssofi.baseURL);
        wr.response.sendRedirect("?openid.mode=confirmForm&email="+URLEncoder.encode(userId, "UTF-8"));
    }


    /*
     * The email contains this link:
     *
     * {baseURL}?openid.mode=validateKeyAction
     *          &registerEmail={emailId}
     *          &registeredEmailKey={magicNumber}
     *          &app={application return URL}
     *
     * so if you get both of those, and they match, then you have validated
     * a particular email address.
     *
     * Generally this method is called only when you are NOT
     * logged in.  If you are already logged it just redirects
     * immediately to the remote destination.
     */
    private void modeValidateKeyAction() throws Exception {
        String registerEmail = reqParam("registerEmail");
        String confirmKey = reqParam("registeredEmailKey").trim();
        aSession.return_to = defParam("app", aSession.return_to);

        UserInformation ui = ssofi.authStyle.getOrCreateUser(registerEmail);

        if (aSession.loggedIn()) {
            if (aSession.loggedUserId().equalsIgnoreCase(registerEmail)) {
                //if user already logged in, as the correct person,
                //check to see if the user password has been set
                //correctly.  If so, go ahead and redirect to the
                //application as if it was a normal link.
                if (ui.hasPassword) {
                    wr.response.sendRedirect(aSession.return_to);
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
                wr.response.sendRedirect("?openid.mode=registerForm");
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
        boolean valid = ssofi.tokenManager.validateAndConsume(registerEmail, confirmKey);
        aSession.presumedId = registerEmail;
        requestedIdentity = null;

        if (!valid) {
            aSession.regEmail = registerEmail;
            aSession.saveError( new Exception(
                    "If you have set up a password, please log in.  "
                    +"If not, request a new email registration email message.  "
                    +"The confirmation key supplied has expired. "));
            wr.response.sendRedirect("?openid.mode=loginView");
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
            wr.response.sendRedirect("?openid.mode=registerForm");
        }
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
			UserInformation ui = ssofi.authStyle.getOrCreateUser(loggedId);
			aSession.login(loggedId, ui.fullName);
            loggedOpenId = AddressParser.composeOpenId(loggedId);

            // This is a 'low security' cookie.  It keeps the Id of the usr
            // that successfully logged in so that next time we can
            // remember and save the user having to type in again.
            // But there is no security value here.
            Cookie userIdCookie = new Cookie("SSOFIUser", loggedId);
            userIdCookie.setMaxAge(31000000); // about 1 year
            userIdCookie.setPath("/"); // everything on the server
            wr.response.addCookie(userIdCookie);
        }
    }


    public String getBestGuessId() {
        if (aSession.loggedIn()) {
            return aSession.loggedUserId();
        }
        else if (requestedIdentity!=null) {
            return requestedIdentity.getUserId();
        }
        else if (aSession.presumedId!=null && aSession.presumedId.length()>0){
            return aSession.presumedId;
        }
        else {
            return ssofi.findCookieValue(wr,"SSOFIUser");
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
        ServletContext sc = wr.session.getServletContext();
        String path = sc.getRealPath("/$/" + resourceName);

        if (resourceName.endsWith(".css")) {
            wr.response.setContentType("text/css");
        }

        TemplateStreamer.streamRawFile(wr.outStream, new File(path));
    }

    private void streamTemplate(String fileName) throws Exception {
        javax.servlet.ServletContext sc2 = wr.session.getServletContext();
        File ctxPath = new File(sc2.getRealPath("/"));

        // fist check to see if a special auth style specific version exists
        if (ssofi.authStyle != null) {
            String testName = fileName + "." + ssofi.authStyle.getStyleIndicator() + ".htm";
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
            wr.response.setContentType("text/html;charset=UTF-8");

            //Why are we tellilng IE how to behave?  Because IE can be set into a mode that causes it to
            //run emulation of IE7, even though it is a much more recent browser.  It ignores the fact that
            //it is more recent, and emulates the old browser unnecessarily.  This appears to be an administration
            //option that allow an organization to run all IE as if they were an older IE.
            //This command says to act like IE 10.  Would be better if we could say IE10 and above.
            //Not all versions of IE obey this command.  Microsoft say that the best practice is to put
            //this in a header, and not a meta-tag because a metatag will slow down handling of the page becausei
            //it has to start parsing all over again.  We don't really want 10, but there seems no setting for
            //IE11 and I am worried that older browsers wont know what Edge is.
            wr.response.setHeader("X-UA-Compatible", "IE=EmulateIE10");

            Writer out = wr.w;
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
                jo.put("isLDAP", ssofi.isLDAPMode);
                jo.put("isLocal", !ssofi.isLDAPMode);
                if (aSession.loggedIn()) {
                    jo.put("userId", aSession.loggedUserId());
                    jo.put("userEmail", aSession.regEmail);
                    UserInformation userInfo = ssofi.authStyle.getOrCreateUser(aSession.loggedUserId());
                    if (userInfo.exists) {
                        jo.put("userKey", userInfo.key);
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
                for (String msg : aSession.getErrorList()) {
                    errors.put(msg);
                    errStr = errStr + msg + "\n ";
                }
                jo.put("userError", errStr);
                jo.put("errors", errors);
                jo.put("baseUrl", ssofi.baseURL);
                jo.put("go", paramGo);
                jo.write(out,2,12);
            }
            else if ("thisPage".equals(tokenName)) {
                HTMLWriter.writeHtml(out, ssofi.baseURL);
            }
            else if ("root".equals(tokenName)) {
                HTMLWriter.writeHtml(out, ssofi.baseURL);
            }
            else if ("serverError".equals(tokenName)) {
                writeHtmlException(out, ssofi.initFailure);
            }
            else if ("userError".equals(tokenName)) {
                for (String eMsg : aSession.getErrorList()) {
                    HTMLWriter.writeHtml(out, eMsg);
                    out.write("\n");
                }
            }
            else if ("captcha".equals(tokenName)) {
                String cerr = null;
                ArrayList<String> eList = aSession.getErrorList();
                if (eList.size()>0) {
                    cerr = eList.get(0);
                }
                out.write(ssofi.securityHandler.getCaptchaHtML(cerr));
            }
            else {
                //if we don't know what it means, write it back out, because
                //it might be a AngularJS token which needs to be transmitted.
                HTMLWriter.writeHtml(out, "{{" + tokenName + "}}");
            }
        }
        catch (Exception e) {
        	//NOTE: we are writing tokens into a template that appears in the browser.
        	//throwing an exception is causing infinite redirect
        	//instead output the exception into the page as a comment

        	HTMLWriter.writeHtml(out, "EXCEPTION (" + tokenName + ")");
        	out.write("\n<!--\n");
        	JSONException.convertToJSON(e, "EXCEPTION (" + tokenName + ")")
        	        .write(out, 2, 2);
        	out.write("\n-->\n");

        	//ALSO put it into the system log
        	JSONException.traceException(e, "EXCEPTION while printing token "+tokenName);
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
        JSONException.convertToJSON(anException, "").write(out,2,2);
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


    @Override
    public void closeLoop(String arg0) throws Exception {
        throw new Exception("SSOFI Template Streamer can not handle LOOPS");
    }

    @Override
    public int initLoop(String arg0, String arg1) throws Exception {
        throw new Exception("SSOFI Template Streamer can not handle LOOPS");
    }

    @Override
    public void setIteration(String arg0, int arg1) throws Exception {
        throw new Exception("SSOFI Template Streamer can not handle LOOPS");
    }

    @Override
    public void debugDump(Writer arg0) throws Exception {
        // TODO Auto-generated method stub
        // NOTE: should switch to using ChunkTemplates ....
        throw new Exception("debugDump not implemented");
    }

    @Override
    public boolean ifValue(String arg0) throws Exception {
        // TODO Auto-generated method stub
        // NOTE: should switch to using ChunkTemplates ....
        throw new Exception("ifValue not implemented");
    }

    @Override
    public void writeTokenDate(Writer arg0, String arg1, String arg2)
            throws Exception {
        // TODO Auto-generated method stub
        // NOTE: should switch to using ChunkTemplates ....
        throw new Exception("writeTokenDate not implemented");
    }

    @Override
    public void writeTokenValueRaw(Writer arg0, String arg1) throws Exception {
        // TODO Auto-generated method stub
        // NOTE: should switch to using ChunkTemplates ....
        throw new Exception("writeTokenValueRaw not implemented");
    }


}
