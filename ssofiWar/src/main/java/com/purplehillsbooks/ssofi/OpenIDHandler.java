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
import java.util.List;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletContext;

import com.purplehillsbooks.json.SimpleException;
import com.purplehillsbooks.json.JSONObject;
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
 *
 * rootURL is usually https://server:port/ssofi
 *
 * ADDRESSES SUPPORTED:
 *
 * --this is the default
 * {rootURL}/xxx?ss={session}&openid.mode=displayForm
 *
 * --this is the modern API used by SLAP.js
 * {rootURL}/xxx?ss={session}&openid.mode=apiWho
 * {rootURL}/xxx?ss={session}&openid.mode=apiGenerate
 * {rootURL}/xxx?ss={session}&openid.mode=apiVerify
 * {rootURL}/xxx?ss={session}&openid.mode=apiLogout
 * {rootURL}/xxx?ss={session}&openid.mode=quick
 * {rootURL}/xxx?ss={session}&openid.mode=apiSendInvite
 *
 * {rootURL}/xxx?ss={session}&openid.mode=logout
 * {rootURL}/xxx?ss={session}&openid.mode=loginAction
 * {rootURL}/xxx?ss={session}&openid.mode=logoutAction
 * {rootURL}/xxx?ss={session}&openid.mode=passwordForm
 * {rootURL}/xxx?ss={session}&openid.mode=passwordAction
 * {rootURL}/xxx?ss={session}&openid.mode=requestForm
 * {rootURL}/xxx?ss={session}&openid.mode=registerNewAction
 * {rootURL}/xxx?ss={session}&openid.mode=confirmForm
 * {rootURL}/xxx?ss={session}&openid.mode=validateKeyAction
 *
 */
public class OpenIDHandler implements TemplateTokenRetriever {

    private static SSOFI ssofi;


    //MEMBER VARIABLES
    WebRequest wr;

    private boolean isPost = false;

    AuthSession aSession;
    boolean saveSession = false;
    boolean destroySession = false;

    //private String loggedOpenId;


    // This is the user that is attempting to log in, which
    // might have been passed as part of the protocol to
    // request authentication, or it might come from the
    // cookies that remember who you logged in as last time.
    //private AddressParser requestedIdentity = null;

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
            String mode = wr.defParam("openid.mode", "displayForm");

            //the verify can be done without any session and by anyone, so
            //to simplify the handling of the session, identify this kind
            //of request here, and handle quickly, before looking for session.
            if ("apiVerify".equals(mode)) {
                ChallengeTokenManager.handleVerifyRequest(wr);
                return;
            }

            sessionId = ssofi.getSSOFISessionId(wr);

            if (ssofi.sHand==null) {
                streamTemplate("configErrScreen");
                return;
            }
            aSession = ssofi.sHand.getAuthSession(wr, sessionId);

            doGetWithSession(mode);
            // doGetWithSession never throws an exception, which means that this
            // is being saved whether an error occurs or not! That is the right
            // thing because the session object holds the error message for the
            // next page
            if (destroySession) {
                ssofi.sHand.deleteAuthSession(sessionId);
            }
            else if (saveSession) {
                ssofi.sHand.saveAuthSession(aSession);
            }
        }
        catch (Exception e) {
            //this exception is not from the operational logic, but the preparation
            //logic or finalization logic which does not deserve sending results
            System.out.println("SSOFI: !!! Error getting or saving session information !!!  at "+AuthSession.currentTimeString());
            SimpleException.traceException(e, "GET: session: "+sessionId
                     +" at "+AuthSession.currentTimeString());
        }
    }

    /**
     * an instance of this is created and called on a single thread
     */
    public void doPost() {
        try {
            isPost = true;
            String postType = wr.request.getHeader("Content-Type");
            if (postType==null
                    || (!postType.toLowerCase().startsWith("text/plain")
                       && !postType.toLowerCase().startsWith("application/json"))) {
                //now get the posted value
                //believe it or not, some idiot decided that application/json was a security
                //hazard, and browsers WILL NOT post content cross domains, even if you
                //say it is OK, in application/json.  But they allow text/plain.
                //So call it EITHER text/plain or application/json and then parse it.
                throw new Exception("SSOFI: doPost but can not understand Content-Type: "+postType);
            }

            //this does not throw anything, but only call if above successful
            doGet();
        }
        catch (Exception e) {
            System.out.println("SSOFI: !!! Unable to handle post to: "+wr.requestURL
                     +" at "+AuthSession.currentTimeString());
            SimpleException.traceException(e, "POST failed to "+wr.requestURL);
        }
    }
/*
    private void assertPost(String mode) throws Exception {
        if (!isPost) {
            throw new SimpleException("The request for mode (%s) must be a POST request.", mode);
        }
    }
    */
    private void assertGet(String mode) throws Exception {
        if (isPost) {
            throw new SimpleException("The request for mode (%s) must be a GET request.", mode);
        }
    }


    private void reDirectHome() throws Exception {
        wr.response.sendRedirect("?openid.mode=displayForm&ss="+aSession.sessionId);
    }

    private void redirectBackToCaller() throws Exception {
        if ((aSession.return_to != null) && (aSession.return_to.length() > 0)) {
            wr.response.sendRedirect(aSession.return_to);
        }
        else {
            wr.response.sendRedirect("?openid.mode=displayForm&ss="+aSession.sessionId);
        }
    }



    /**
     * Handles the request with the assumption that the session object has been
     * fetched, and will be saved afterwards.
     */
    public void doGetWithSession(String mode) {
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
            if (aSession.loggedIn()) {
                wr.setCookie("SSOFIUser", aSession.loggedUserId());
            }

            if (!requestURL.startsWith(ssofi.rootURL)) {
                throw new SimpleException("sorry, request must start with (%s):  (%s)", ssofi.rootURL, requestURL);
            }

            //this is rootURL + "$/" and it is for the bits and pieces for the page
            if (requestURL.startsWith(ssofi.knownAssetPath)) {
                serveUpAsset(requestURL.substring(ssofi.knownAssetPath.length()));
                return;
            }

            if (mode.startsWith("api")) {
                // Want to avoid saving a session as a result of every API call.  The API call will never
                // add or remove a session, it is only used to verify existing sessions.  In general API
                // round trips should be fast ... only a few seconds ... so persistence is not an
                // issue.  The problem is API calls made from the server do not preserve cookies, and a
                // new session is started every access, causing a flood of sessions, each potentially
                // lasting for a long time (a month) so persisting these sessions would be a waste.
                saveSession = false;
                APIHelper theApi = new APIHelper(aSession, wr, ssofi);
                destroySession = theApi.handleAPICommand(mode);
                if (destroySession) {
                    //clear out any existing session id
                    SSOFI.createSSOFISessionId(wr);
                }
                return;
            }

            // anything below here is LIKELY to change the session
            saveSession = true;


            if ("quick".equals(mode)) {
                aSession.return_to = reqParam("go");
                if (aSession.loggedIn()) {
                    //user is logged in, so just jump back
                    //we don't care if logged in as a different user.
                    //preserve the current logged in user session
                    System.out.println("SSOFI ("+aSession.sessionId+"): successful quick confirmation of user: "
                            +aSession.loggedUserId()+" at "+AuthSession.currentTimeString());
                    this.redirectBackToCaller();
                }
                else {
                    if (aSession.presumedId==null || aSession.presumedId.length()==0) {
                        //pick up the cookie value if it exists
                        String emailPassed = wr.findCookieValue("SSOFIUser");
                        if (emailPassed!=null && emailPassed.length()>0) {
                            aSession.presumedId = emailPassed;
                        }
                    }
                    saveSession = true;
                    System.out.println("SSOFI ("+aSession.sessionId+"): quick check found user was not logged in at "+AuthSession.currentTimeString());
                    reDirectHome();
                }
            }
            else if ("validateKeyAction".equals(mode)) {
                //this can be GET or POST, and can be done while logged in or not
                //this will log you in if all is proper
                modeValidateKeyAction();
            }
            else {
                if (!"loginView".equals(mode) && !"displayForm".equals(mode)) {
                    throw new SimpleException("Don't understand the mode (%s)", mode);
                }
                assertGet(mode);
                // login or display or display any kind of error
                displayRootPage();
            }

        }
        catch (Exception eorig) {
        	try {
                aSession.saveError(eorig, "EXCEPTION during doGetWithSession");
                ssofi.sHand.saveAuthSession(aSession);
                reDirectHome();
            }
            catch (Exception eeeee) {
                SimpleException.traceException(eeeee, "EXCEPTION during EXCEPTION - doGetWithSession");
            }
        }
    }


    /*
    private void setRequestedId() throws Exception  {
        String email = wr.request.getParameter("email");
        if (email!=null) {
            requestedIdentity = new AddressParser(ssofi.baseURL + email);
        }
    }
    */

    /**
     * get the value directly from the current request object
     */
    String reqParam(String name) throws Exception {

        return wr.reqParam(name);
    }

    /**
     * get the value directly from the current request object
     */
    String defParam(String name, String defaultVal) throws Exception {

        return wr.defParam(name, defaultVal);
    }




    /**
     * Root page is the page that is displayed when no user is specified. This
     * is the place where you can enter a user id
     */
    private void displayRootPage() throws Exception {
        System.out.println("SSOFI ("+aSession.sessionId+"): displayed the root page for user at "+AuthSession.currentTimeString());
        streamTemplate("justAnonymous");
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
        
        //anyone clicking on a validate link should forget about any possible earlier 
        //email confirmations they had.   Those no longer matter.
        aSession.clearConfirmBit();

        //if failing to use a link, fail BEFORE testing the link
        if (aSession.loggedIn()) {
            if (!aSession.loggedUserId().equalsIgnoreCase(registerEmail))  {
	            System.out.println("SSOFI: Logged-in user attempt to use email link: "+wr.request.getQueryString()
                     +" at "+AuthSession.currentTimeString());
	
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
                throw new SimpleException("Sorry there is a problem.  You are logged in as %s.  "
                        +"%s but you have clicked on a link validating the email for "
                        +"If you wish to validate that other email address, please logout before clicking on the link again.",
                        aSession.loggedUserId(), registerEmail);
            }
        }        

        aSession.presumedId = registerEmail;
        UserInformation ui = ssofi.authStyle.getOrCreateUser(registerEmail);
        boolean valid = ssofi.tokenManager.validateAndConsume(registerEmail, confirmKey);
        if (valid) {
            //this token is still valid link, so mark the session that email confirmed
            //so that they can change their password if desired.
            aSession.emailConfirmed(ui);
        }

        //if logged in AND same email address, then it does not matter if link is valid
        //we allow chaning password anyway.
        if (aSession.loggedIn()) {
            System.out.println("SSOFI: Logged-in user attempt to use email link: "+wr.request.getQueryString()+" at "+AuthSession.currentTimeString());

            // User has already logged in, as the correct person,
            // check to see if the user is expecting to set password
            // specifically: the processing of a valid link causes justConfirmed==true
            // and if it is NOT justConfirmed, then just return to the application
            // that originally called, nothing left to do here.
            // That original password setting link just acts like a return to app.

            if (!aSession.hasJustConfirmed()) {
                redirectBackToCaller();
                return;
            }

            //The only way they can get here, being logged in, but not having
            //set a password, is if they got the password setting prompt, and
            //then closed the window -- without losing their session.
            //Can anyone steal their session?
            //Can someone jump in an set their password before they had a chance?
            //good questions.   On the assumption this is not a real danger,
            //go ahead and prompt again to set the password, because they
            //probably clicked on the link again, to try again to set password.
            aSession.presumedId = registerEmail;
            reDirectHome();
            return;
        }


        if (!valid) {
            System.out.println("SSOFI: Anonymous attempt to use email link that is not valid: "+wr.request.getQueryString()+" at "+AuthSession.currentTimeString());
            throw new Exception(
                    "The confirmation key supplied has expired. "
                    +"If you have set up a password, please log in.  "
                    +"If not, request a new email registration email message.");
        }

        if (valid) {
        	//now the user is officially logged in
            setLogin(registerEmail);

            //always go to register because they might have chose this link in order to reset their password
            reDirectHome();
        }
    }
        



    /**
     * Set to null to clear the login
     */
    
    private void setLogin(String loggedId) throws Exception {
        if (loggedId == null) {
            aSession.logout();
        }
        else {
			UserInformation ui = ssofi.authStyle.getOrCreateUser(loggedId);
			aSession.setUserOnSession(ui);

            // This is a 'low security' cookie.  It keeps the Id of the usr
            // that successfully logged in so that next time we can
            // remember and save the user having to type in again.
            // But there is no security value here.
            wr.setCookie("SSOFIUser", loggedId);
            System.out.println("SSOFI ("+aSession.sessionId+"): login successful for user: "+aSession.loggedUserId()+" at "+AuthSession.currentTimeString());
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
        jakarta.servlet.ServletContext sc2 = wr.session.getServletContext();
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
                out.write("SESSION = "+aSession.sessionId);
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
                JSONObject jo = aSession.userStatusAsJSON(ssofi);
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
                aSession.clearError();
            }
            else if ("captcha".equals(tokenName)) {
                String cerr = null;
                List<String> eList = aSession.getErrorList();
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
        	SimpleException.convertToJSON(e, "EXCEPTION (" + tokenName + ")")
        	        .write(out, 2, 2);
        	out.write("\n-->\n");

        	//ALSO put it into the system log
        	SimpleException.traceException(e, "EXCEPTION while printing token "+tokenName);
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
        SimpleException.convertToJSON(anException, "").write(out,2,2);
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
        // NOTE: should switch to using ChunkTemplates ....
        throw new Exception("debugDump not implemented");
    }

    @Override
    public boolean ifValue(String arg0) throws Exception {
        // NOTE: should switch to using ChunkTemplates ....
        throw new Exception("ifValue not implemented");
    }

    @Override
    public void writeTokenDate(Writer arg0, String arg1, String arg2)
            throws Exception {
        // NOTE: should switch to using ChunkTemplates ....
        throw new Exception("writeTokenDate not implemented");
    }

    @Override
    public void writeTokenValueRaw(Writer arg0, String arg1) throws Exception {
        // NOTE: should switch to using ChunkTemplates ....
        throw new Exception("writeTokenValueRaw not implemented");
    }


}
