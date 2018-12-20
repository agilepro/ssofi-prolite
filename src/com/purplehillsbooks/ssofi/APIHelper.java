package com.purplehillsbooks.ssofi;

import java.io.Writer;

import javax.servlet.http.HttpServletResponse;

import com.purplehillsbooks.json.JSONException;
import com.purplehillsbooks.json.JSONObject;

public class APIHelper {

	private JSONObject postedObject;
	private AuthSession aSession;
	private HttpServletResponse response;
	private EmailHandler emailHandler = null;
	private EmailTokenManager tokenManager;
	boolean destroySession = false;
	
	public static String baseURL;

	public APIHelper(AuthSession _aSession, JSONObject _postedObject, HttpServletResponse _response,
			EmailHandler _emailHandler, EmailTokenManager _tokenManager) {
		aSession     = _aSession;
		postedObject = _postedObject;
		response     = _response;
		emailHandler = _emailHandler;
		tokenManager = _tokenManager;
    }

    public boolean handleAPICommand(String mode) throws Exception {
        try {
        	JSONObject responseObj = getResponse(mode);
        	sendJSON(200, responseObj);
        }
        catch(Exception e) {
            JSONException.traceException(e, "handleAPICommand: mode="+mode);
            JSONObject jo = JSONException.convertToJSON(e, "SSOFI LAuth EXCEPTION mode="+mode);
            sendJSON(200, jo);
        }
        return destroySession;
    }


    private JSONObject getResponse(String mode) throws Exception {
        //do not need to be logged in to verify a token
        if ("apiVerify".equals(mode)) {
            if (postedObject==null) {
                throw new Exception("Received a request for verifying a token without any posted JSON information");
            }
            String identity  = postedObject.getString("userId");
            String challenge = postedObject.getString("challenge");
            String token     = postedObject.getString("token");
            AuthSession auth = AuthSession.verifyToken(identity, challenge, token);
            if (auth!=null) {
                JSONObject responseObj = new JSONObject();
                responseObj.put("userId", auth.loggedUserId());
                String name = auth.loggedUserName();
                responseObj.put("userName", name);
                if (name==null || name.length()==0) {
                    responseObj.put("userName", "User: "+auth.loggedUserId());
                }
                responseObj.put("challenge", challenge);  //do we need this?
                responseObj.put("token", token);          //do we need this?
                responseObj.put("verified", true);
                responseObj.put("msg", "Token matches with the challenge");
                System.out.println("SSOFI LAuth request: apiVerify success: "+identity);
                return responseObj;
            }
            else {
                postedObject.put("msg", "failure, the token does not match");
                postedObject.remove("userId");
                postedObject.remove("userName");
                postedObject.put("verified", false);
                System.out.println("SSOFI LAuth request: apiVerify FAILED to verify: "+identity);
                return postedObject;
            }
        }
        if ("apiLogout".equals(mode)) {
            //whether you are logged in or not, you get the same response
            //from this command:  you are now logged out.
            System.out.println("SSOFI LAuth request: apiLogout logged out: "+aSession.loggedUserId());
            
            aSession.logout();
            destroySession = true;
            JSONObject jo = new JSONObject();
            jo.put("msg", "User logged out");
            return jo;
        }
        if ("apiSendInvite".equals(mode)) {
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
            return okResponse;
        }
        if (!aSession.loggedIn()) {
            System.out.println("SSOFI LAuth request: not logged in, not allowed: "+mode);
            JSONObject jo = new JSONObject();
            jo.put("msg", "User not found, must be logged in to perform "+mode);
            return jo;
        }
        System.out.println("SSOFI LAuth request: "+mode+" - "+aSession.loggedUserId());
        if ("apiWho".equals(mode)) {
            JSONObject jo = new JSONObject();
            jo.put("msg", "User logged in");
            jo.put("userId",   aSession.loggedUserId());
            jo.put("userName", aSession.loggedUserName());
            return jo;
        }
        if ("apiGenerate".equals(mode)) {
            if (postedObject==null) {
                throw new Exception("Received a request for generating a token without any posted JSON information");
            }
            String challenge = postedObject.getString("challenge");
            String token = aSession.generateToken(challenge);
            postedObject.put("userId",   aSession.loggedUserId());
            postedObject.put("userName", aSession.loggedUserName());
            postedObject.put("token",    token);
            return postedObject;
        }
        throw new Exception("Authentication API can not understand mode "+mode);
    }


    private void sendInviteEmail(String userId, String userName, String msg, String returnUrl, String subject, String baseURL) throws Exception {
        if (!emailHandler.validate(userId)) {
            throw new Exception("The id supplied (" + userId
                    + ") does not appear to be a valid email address.");
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
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(code);
        Writer out = response.getWriter();
        jo.write(out,2,0);
        out.flush();
    }

}
