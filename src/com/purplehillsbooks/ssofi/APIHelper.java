package com.purplehillsbooks.ssofi;

import java.io.Writer;
import java.util.Properties;

import com.purplehillsbooks.json.JSONException;
import com.purplehillsbooks.json.JSONObject;

public class APIHelper {

    private SSOFI ssofi;
    private JSONObject postedObject;
	private AuthSession aSession;
	private WebRequest wr;
	private EmailHandler emailHandler = null;
	private EmailTokenManager tokenManager;
	boolean destroySession = false;

	public static String baseURL;

	public APIHelper(AuthSession _aSession, JSONObject _postedObject, WebRequest _wr,SSOFI _ssofi) {
	    wr           = _wr;
		aSession     = _aSession;
		postedObject = _postedObject;
		ssofi        = _ssofi;
		emailHandler = ssofi.emailHandler;
		tokenManager = ssofi.tokenManager;
    }

	public void setPostObject(JSONObject newPost) {
	    postedObject = newPost;
	}


	public JSONObject verifyToken() throws Exception {
        if (postedObject==null) {
            throw new Exception("Received a request for verifying a token without any posted JSON information");
        }
        String identity  = postedObject.getString("userId");
        String challenge = postedObject.getString("challenge");
        String token     = postedObject.getString("token");
        AuthSession auth = AuthSession.verifyToken(identity, challenge, token);
        if (auth!=null) {
            JSONObject responseObj = auth.userAsJSON(ssofi);
            responseObj.put("challenge", challenge);  //do we need this?
            responseObj.put("token", token);          //do we need this?
            responseObj.put("verified", true);
            responseObj.put("msg", "Token matches with the challenge");
            System.out.println("SSOFI LAuth request: apiVerify success: "+identity);
            return responseObj;
        }
        else {
            postedObject.put("msg", "failure, the token does not match");
            postedObject.put("ss", aSession.sessionId);
            postedObject.remove("userId");
            postedObject.remove("userName");
            postedObject.put("verified", false);
            System.out.println("SSOFI LAuth request: apiVerify FAILED to verify: "+identity);
            return postedObject;
        }
	}

    public JSONObject login() throws Exception {
        aSession.clearError();
        // this takes the action of logging the user in, and returning if all OK
        // first see if they pressed the Cancel key
        String userId = postedObject.getString("userId");
        String password = postedObject.getString("password");

        //if already logged in
        if (aSession.loggedIn()) {
            if (aSession.loggedUserId().equalsIgnoreCase(userId)) {
                //if already to this particular name, then don't change anything
                return aSession.userAsJSON(ssofi);
            }
            else {
                //since the name changed, log out just to be sure
                aSession.logout();
            }
        }

        if (ssofi.authStyle.authenticateUser(userId, password)) {
            UserInformation ui = ssofi.authStyle.getOrCreateUser(userId);
            aSession.login(ui);
            ssofi.sHand.saveAuthSession(aSession);

            // This is a 'low security' cookie.  It keeps the Id of the usr
            // that successfully logged in so that next time we can
            // remember and save the user having to type in again.
            // But there is no security value here.
            wr.setCookie("SSOFIUser", userId);
            aSession.presumedId = userId;
            return aSession.userAsJSON(ssofi);
        }
        else {
            throw new Exception("Unable to log you in to user id (" + userId
                    + ") with that password.  Please try again or reset your password.");
        }
    }

    public JSONObject logout() throws Exception {
        aSession.clearError();
        //whether you are logged in or not, you get the same response
        //from this command:  you are now logged out.
        if (aSession.loggedIn()) {
            aSession.logout();

            //this deletes the file if there is one
            ssofi.sHand.deleteAuthSession(aSession.sessionId);

            //this changes it session ID so that all new interactions are on a new ID
            aSession.changeSessionId(SSOFI.createSSOFISessionId(wr));
            ssofi.sHand.saveAuthSession(aSession);
        }
        return aSession.userAsJSON(ssofi);
	}

    public JSONObject sendInvite() throws Exception {
        aSession.clearError();
        if (postedObject==null) {
            throw new Exception("Received a request for sending email without any posted JSON information");
        }
        //remember, this user ID is NOT the logged in user who is requesting the invitation
        //but instead the user who is being sent the invitation.
        String userId = postedObject.getString("userId");
        String userName = postedObject.optString("userName");
        String msg = postedObject.getString("msg");
        String returnUrl = postedObject.getString("return");
        String subject = postedObject.optString("subject", "Invitation to Collaborate");
        sendInviteEmail(userId, userName, msg, returnUrl, subject, baseURL);
        JSONObject okResponse = new JSONObject();
        okResponse.put("result", "ok");
        okResponse.put("userId", userId);
        return okResponse;
    }

    public JSONObject whoAmI() throws Exception {
        return aSession.userAsJSON(ssofi);
    }
    public JSONObject setPassword() throws Exception {
        aSession.clearError();
        try {
            if (!aSession.loggedIn()) {
                System.out.println("SSOFI: attempt to change password when not logged in: "+aSession.sessionId);
                throw new Exception("Not currently logged in.");
            }
            if (postedObject==null) {
                throw new Exception("to change a password there must be a posted JSON object");
            }
            UserInformation userInfo = null;
            if (aSession.hasJustConfirmed()) {
                //just call this to make sure that the user object exists in the file
                userInfo = ssofi.authStyle.getOrCreateUser(aSession.emailTested);
            }
            else {
                userInfo = ssofi.authStyle.getExistingUserOrNull(aSession.loggedUserId());
                if (userInfo == null) {
                    throw new JSONException("Unable to set password because user {0} does not exist, and email has not been confirmed.", aSession.emailTested);
                }
                String oldPwd = postedObject.optString("oldPwd");
                if (oldPwd==null) {
                    throw new Exception("Must pass 'oldPwd' when setting password, and when you have not just confirmed the email address.");
                }
                if (!ssofi.authStyle.authenticateUser(aSession.loggedUserId(), oldPwd)) {
                    throw new JSONException("The 'oldPwd' submitted does not appear to be the correct one for user {0}", aSession.emailTested);
                }
            }

            String newPwd = postedObject.getString("newPwd");
            ssofi.authStyle.setPassword(aSession.loggedUserId(), newPwd);
            aSession.clearConfirmBit();
            ssofi.sHand.saveAuthSession(aSession);

            return aSession.userAsJSON(ssofi);
        }
        catch (Exception e) {
            throw new JSONException("Unable to set password for user ({0})",  e, aSession.loggedUserId());
        }
    }
    public JSONObject setName() throws Exception {
        aSession.clearError();
        try {
            if (!aSession.loggedIn()) {
                System.out.println("SSOFI: attempt to change name when not logged in: "+aSession.sessionId);
                throw new Exception("Not currently logged in.");
            }
            if (postedObject==null) {
                throw new Exception("To change a name there must be a posted JSON object.");
            }
            if (aSession.hasJustConfirmed()) {
                //this might be the very first save, so create user if necessary
                ssofi.authStyle.getOrCreateUser(aSession.loggedUserId());
            }
            String fullName = postedObject.getString("fullName");
            ssofi.authStyle.changeFullName(aSession.loggedUserId(), fullName);
            aSession.updateFullName(fullName);
            ssofi.sHand.saveAuthSession(aSession);
            return aSession.userAsJSON(ssofi);
        }
        catch (Exception e) {
            throw new JSONException("Unable to set name for user {0}",  e, aSession.loggedUserId());
        }
    }
    public JSONObject sendPasswordReset() throws Exception {
        aSession.clearError();
        if (postedObject==null) {
            throw new Exception("Received a request for sending email without any posted JSON information");
        }
        String registerEmail = postedObject.getString("registerEmail").trim();
        if (!ssofi.emailHandler.validAddressFormat(registerEmail)) {
            throw new Exception("The id supplied (" + registerEmail
                    + ") does not appear to be a valid email address.");
        }

        // Security check
        aSession.saveParameterList(wr.request);
        Properties secProp = new Properties();
        secProp.put(SecurityHandler.REGIS_REQ_REMOTE_IP, wr.request.getRemoteAddr());
        secProp.put(SecurityHandler.REGIS_REQ_EMAILID, registerEmail);
        secProp.put(SecurityHandler.CAPTCHA_CHALLANGE_REQ,
                wr.defParam(SecurityHandler.CAPTCHA_CHALLANGE_REQ, ""));
        secProp.put(SecurityHandler.CAPTCHA_CHALLANGE_RESP,
                wr.defParam(SecurityHandler.CAPTCHA_CHALLANGE_RESP, ""));


        //this appears to only check the Captcha
        ssofi.securityHandler.validate(secProp);


        aSession.presumedId = registerEmail;

        aSession.savedParams.clear();
        String magicNumber = ssofi.tokenManager.generateEmailToken(registerEmail);
        aSession.startRegistration(registerEmail);
        ssofi.emailHandler.sendVerifyEmail(registerEmail, magicNumber, aSession.return_to, ssofi.baseURL);
        ssofi.sHand.saveAuthSession(aSession);
        return aSession.userAsJSON(ssofi);
    }



    public JSONObject generateToken() throws Exception {
        aSession.clearError();
        if (!aSession.loggedIn()) {
            System.out.println("SSOFI: attempt to generate token when not logged in: "+aSession.sessionId);
            return aSession.userAsJSON(ssofi);
        }
        if (postedObject==null) {
            throw new Exception("Received a request for generating a token without any posted JSON information");
        }
        String challenge = postedObject.getString("challenge");
        String token = aSession.generateToken(challenge);
        postedObject.put("ss",       aSession.sessionId);
        postedObject.put("userId",   aSession.loggedUserId());
        postedObject.put("userName", aSession.loggedUserName());
        postedObject.put("token",    token);
        return postedObject;
    }

    public boolean handleAPICommand(String mode) throws Exception {
        try {
        	JSONObject responseObj = getResponse(mode);
        	sendJSON(200, responseObj);
        }
        catch(Exception e) {
            JSONException.traceException(e, "Unable to handle SSOFI request for "+mode);
            JSONObject jo = JSONException.convertToJSON(e, "Unable to handle SSOFI request for "+mode);
            aSession.saveError(e);
            ssofi.sHand.saveAuthSession(aSession);
            sendJSON(400, jo);
        }
        return destroySession;
    }


    private JSONObject getResponse(String mode) throws Exception {
        //do not need to be logged in to verify a token
        if ("apiVerify".equals(mode)) {
            return verifyToken();
        }
        if ("apiLogout".equals(mode)) {
            return logout();
        }
        if ("apiSendInvite".equals(mode)) {
            return sendInvite();
        }
        if (!aSession.loggedIn()) {
            System.out.println("SSOFI LAuth request: not logged in, not allowed: "+mode);
            return aSession.userAsJSON(ssofi);
        }
        System.out.println("SSOFI LAuth request: "+mode+" - "+aSession.loggedUserId());
        if ("apiWho".equals(mode)) {
            return whoAmI();
        }
        if ("apiGenerate".equals(mode)) {
            return generateToken();
        }
        throw new JSONException("Authentication API can not understand mode {0}", mode);
    }


    private void sendInviteEmail(String userId, String userName, String msg, String returnUrl, String subject, String baseURL) throws Exception {
        if (!emailHandler.validAddressFormat(userId)) {
            throw new JSONException("The id supplied ({0}) does not appear to be a valid email address.", userId);
        }
        //The idea here is to slow down any attempt to send email.
        //one user to wait 3 seconds is not a problem, but this will
        //significantly slow down a hacker
        Thread.sleep(3000);
        String magicNumber = tokenManager.generateEmailToken(userId);
        String fromAddress = "weaver@circleweaver.com";
        String fromName = "Weaver";
        if (aSession.loggedIn()) {
            fromAddress = aSession.loggedUserId();
            fromName = aSession.loggedUserName();
        }
        if (userName==null || userName.length()<1) {
            userName = aSession.loggedUserName();
        }
        emailHandler.sendInviteEmail(fromAddress, fromName, userId, msg, subject, magicNumber, returnUrl, baseURL);
    }


    private void sendJSON(int code, JSONObject jo) throws Exception {
        wr.response.setContentType("application/json;charset=UTF-8");
        wr.response.setStatus(code);
        Writer out = wr.w;
        jo.write(out,2,0);
        out.flush();
    }

}
