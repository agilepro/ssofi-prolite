/*
 * Copyright 2015 Fujitsu North America
 */

package com.purplehillsbooks.ssofi;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;

import com.purplehillsbooks.json.JSONObject;

/**
 * This handler is instantiated for every request, so that it can hold onto
 * those values as data members, and not have to pass through all the methods.
 * This object instance represents the entire request, and the methods handle it.s
 *
 * http://{machine:port}/{application}/rest/    ==   {baseurl}
 *
 * The details of course depends upon the host and how to install
 * the application server.  All of that is represented by the
 * symbol {baseurl} for all the discussion below.
 */

public class RestHandler {

    private static SSOFI ssofi;

    APIHelper theHelper;
    WebRequest wr;
    AuthSession aSession;

    boolean isPost;
    JSONObject postBody;

    public RestHandler(WebRequest _wr) throws Exception {
        wr = _wr;
        isPost = wr.isPost();
    }


    /**
     * Handler static variables must be set up before handling any request. This
     * matches the servlet initialization protocol.
     */
    public static void init(ServletConfig config) {
        ServletContext sc = config.getServletContext();
        ssofi = SSOFI.getSSOFI(sc);
    }


    /**
     * Request handler does one of three things:
     * (1) it returns a JSONObject to stream to the caller
     * (2) it throws an exception that will be returned as JSONException
     * (3) it returns null which means response has been streamed already
     *
     * request url:   {baseUrl}/rest/{this}/...
     *
     * In the {this} position you can either have
     *
     *      rest/whoami
     *      rest/login
     *      rest/logout
     *      rest/setpassword
     */
    public JSONObject handleRequest() throws Exception {
        String sessionId = ssofi.getSSOFISessionId(wr);

        if (ssofi.sHand==null) {
            throw new Exception("RestHandler is not innitialized correction");
        }
        aSession = ssofi.sHand.getAuthSession(wr, sessionId);


    	System.out.println("SSOFI REST: "+wr.requestURL);
        if (wr.pathFinished()) {
            //this should not be possible ... there should always be 'api'
            //this is just a consistency check
            throw new Exception("Program Logic Error: unexpected internal path is missing the 'rest' entry from path");
        }
        String zeroToken = wr.consumePathToken();
        if (!"rest".equals(zeroToken)) {
            //this should not be possible ... there should always be 'rest'
            //this is just a consistency check
            throw new Exception("Program Logic Error: the first path element is expected to be 'rest' but was instead '"+zeroToken+"'");
        }
        if (wr.pathFinished()) {
            //if there is nothing after the 'api' then just generate the PING response
            return new JSONObject().put("hello", "world");
        }

        if (isPost) {
            postBody = wr.getPostedObject();
        }
        else {
            postBody = new JSONObject();
        }


        APIHelper theApi = new APIHelper(aSession, postBody, wr, ssofi);
        String firstToken = wr.consumePathToken();
        if ("generateToken".equals(firstToken)) {
            return theApi.generateToken();
        }
        if ("verifyToken".equals(firstToken)) {
            return theApi.verifyToken();
        }
        if ("whoAmI".equals(firstToken)) {
            return theApi.whoAmI();
        }
        if ("login".equals(firstToken)) {
            return theApi.login();
        }
        if ("logout".equals(firstToken)) {
            return theApi.logout();
        }
        if ("setPassword".equals(firstToken)) {
            return theApi.setPassword();
        }
        if ("setName".equals(firstToken)) {
            return theApi.setName();
        }
        if ("sendReset".equals(firstToken)) {
            return theApi.sendPasswordReset();
        }
        if ("sendInvite".equals(firstToken)) {
            return theApi.sendInvite();
        }
        throw new Exception("SSOFI API is unable to understand the first path element: "+firstToken);
    }

}
