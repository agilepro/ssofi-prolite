package com.purplehillsbooks.ssofi;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;

import com.purplehillsbooks.json.JSONObject;
import com.purplehillsbooks.streams.SSLPatch;

public class GoogleHandler {

    private static SSOFI ssofi;

    public static String wellKnownEndpoint = "https://accounts.google.com/.well-known/openid-configuration";
    public static String authorizationEndpoint;
    public static String authScopes;
    public static String clientId = null;
    public static String getTokenEndpoint = "https://oauth2.googleapis.com/token";
    public static String clientSecret = null;
    public static String redirectUri = null;
/* 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 */
    public GoogleHandler() {}

    public static void initialize(SSOFI newSsofi) {

        ssofi = newSsofi;
        redirectUri = ssofi.baseURL + "google";

        if (authorizationEndpoint != null) {
            return;
        }

        try {
            clientId = ssofi.getSystemProperty("googleClientId");
            clientSecret = ssofi.getSystemProperty("googleClientSecret");
            if (clientId==null || clientId.isEmpty()) {
                System.out.println("GOOGLE LOGIN DISABLED - no Client ID");
            }
            if (clientSecret==null || clientSecret.isEmpty()) {
                System.out.println("GOOGLE LOGIN DISABLED - no Client Secret");
            }
            
            HttpClient httpclient = getGoodClient();
         
            HttpGet httpget = new HttpGet(wellKnownEndpoint);

            HttpResponse response = httpclient.execute(httpget);
            JSONObject googleWellKnown = getBodyAsJson(response);

            authorizationEndpoint = googleWellKnown.getString("authorization_endpoint");
            authScopes = "openid email profile";
            System.out.println("GOOGLE login enabled.");
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static JSONObject embeddedData() {
        JSONObject jo = new JSONObject();
        jo.put("authorizationEndpoint", authorizationEndpoint);
        jo.put("authScopes", authScopes);
        jo.put("clientId", clientId);
        jo.put("redirectUri", redirectUri);
        return jo;
    }

    public static JSONObject getBodyAsJson(HttpResponse response) throws Exception {
            InputStream input = response.getEntity().getContent();
            InputStreamReader reader = new InputStreamReader(input, "UTF-8");
            return JSONObject.readFromReader(reader);
    }

    public static UserInformation loggedInResponse(String code, String scope, 
            String authuser, String prompt, AuthSession aSession, WebRequest wr) throws Exception {
        try {
            aSession.clearError();
            
            if (clientId==null || clientId.isEmpty()) {
                throw SsofiException.newBasic("Missing Google client ID");
            }
            if (clientSecret==null || clientSecret.isEmpty()) {
                throw SsofiException.newBasic("Missing Google client secret");
            }        
            // System.out.println("GOOGLE: code="+code);
            // System.out.println("GOOGLE: scope="+scope);
            // System.out.println("GOOGLE: authuser="+authuser);
            // System.out.println("GOOGLE: prompt="+prompt);

            StringBuilder getTokenUrl = new StringBuilder("https://oauth2.googleapis.com/token");

            List<NameValuePair> bodyFields = new ArrayList<>();
            bodyFields.add(new BasicNameValuePair("code", code));
            bodyFields.add(new BasicNameValuePair("client_id", clientId));
            bodyFields.add(new BasicNameValuePair("client_secret", clientSecret));
            bodyFields.add(new BasicNameValuePair("redirect_uri", redirectUri));
            bodyFields.add(new BasicNameValuePair("grant_type", "authorization_code"));
            

            HttpClient httpclient = getGoodClient();
            HttpPost httpPost = new HttpPost(getTokenUrl.toString());
            httpPost.setEntity(new UrlEncodedFormEntity(bodyFields));

            HttpResponse response = httpclient.execute(httpPost);
            JSONObject tokenBody = getBodyAsJson(response);

            System.out.println("GOOGLE RESPONSE: \n"+tokenBody.toString(2));

            if (tokenBody.has("error")) {
                throw SsofiException.newBasic("Error from Google: %s, %s", 
                        tokenBody.getString("error"), 
                        tokenBody.optString("error_description"));
            }
            // String accessToken = tokenBody.getString("access_token");
            String idToken = tokenBody.getString("id_token");
            // String scope2 = tokenBody.getString("scope");
            // String token_type = tokenBody.getString("token_type");

            String[] threeParts = idToken.split("\\.");
            if (threeParts.length != 3) {
                throw SsofiException.newBasic("Not able to parse the idToken as JWT it has "+threeParts.length+" of 3 parts.");
            }
            String claimPart = threeParts[1];

            String decodedClaim = new String(Base64.getDecoder().decode(claimPart), StandardCharsets.UTF_8);

            JSONObject claimObj = new JSONObject(decodedClaim);
            String userEmail = claimObj.getString("email");
            String userName = claimObj.getString("name");

            System.out.println("GOOGLE USER:  email=" +userEmail + ", name=" + userName);
            UserInformation ui = ssofi.authStyle.getOrCreateUser(userEmail);
            ui.fullName = userName;
            aSession.setUserOnSession(ui);
            ssofi.authStyle.changeFullName(aSession.loggedUserId(), userName);
            aSession.updateFullName(userName);
            return ui;
        }
        catch (Exception e) {
            throw SsofiException.newWrap("Failure while attempting Google login", e);
        }
    }

    private static HttpClient getGoodClient() {
        try { 
            TrustStrategy ts = new TrustStrategy() {
                public boolean isTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
                    return true;
                }
            };
            
            SSLContextBuilder scb = new SSLContextBuilder();
            scb.loadTrustMaterial(null, ts);
            
            HttpClientBuilder hcb = HttpClientBuilder.create();
            hcb.setSSLHostnameVerifier(SSLPatch.getAllHostVerifier());
            hcb.setSSLContext(scb.build());
            return hcb.build();
            
        } 
        catch (Exception ex) {
            return null;
        }
    }

}