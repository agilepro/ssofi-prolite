package com.purplehillsbooks.ssofi;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Properties;
import java.util.Vector;

import net.tanesha.recaptcha.ReCaptcha;
import net.tanesha.recaptcha.ReCaptchaFactory;
import net.tanesha.recaptcha.ReCaptchaImpl;
import net.tanesha.recaptcha.ReCaptchaResponse;

public class SecurityHandler {
    private static String captchaPrivateKey = "";
    private static String captchaPublicKey = "";
    private static String blockedIpListFilePath = "";
    private static HashMap<String, UserRegRequest> userRegReqMap = new HashMap<String, UserRegRequest>();

    public static final String CAPTCHA_CHALLANGE_REQ = "recaptcha_challenge_field";
    public static final String CAPTCHA_CHALLANGE_RESP = "recaptcha_response_field";
    public static final String REGIS_REQ_REMOTE_IP = "remoteIp";
    public static final String REGIS_REQ_EMAILID = "emailId";

    public SecurityHandler(String captchaPrivateKey, String captchaPublicKey,
            File blockedIpListFilePath) {

        SecurityHandler.captchaPrivateKey = captchaPrivateKey;
        SecurityHandler.captchaPublicKey = captchaPublicKey;
        SecurityHandler.blockedIpListFilePath = blockedIpListFilePath.getPath();

    }

    public String getCaptchaHtML(String errMessage) {
        // Security is not on.
        if (null == captchaPrivateKey || captchaPrivateKey.length() == 0) {
            return "";
        }
        ReCaptcha c = ReCaptchaFactory.newSecureReCaptcha(captchaPublicKey, captchaPrivateKey,
                false);
        ((ReCaptchaImpl) c).setRecaptchaServer("https://www.google.com/recaptcha/api");
        return c.createRecaptchaHtml(errMessage, null);
    }

    public void validate(Properties prop) throws Exception {
        // Security is not on.
        if (null == captchaPrivateKey || captchaPrivateKey.length() == 0) {
            return;
        }

        if (isBlockedIp(prop)) {
            throw new Exception("Security Validation Failed. Prohibited");
        }

        validateCaptchaEntry(prop);

        if (userRegReqMap.size() > 1000) {
            cleanUserReqMap();
        }

        // Update userReqMap
        String remoteAddr = prop.getProperty(REGIS_REQ_REMOTE_IP);
        String emailId = prop.getProperty(REGIS_REQ_EMAILID);
        UserRegRequest urr = userRegReqMap.get(remoteAddr);
        if (urr == null) {
            urr = new UserRegRequest(remoteAddr, blockedIpListFilePath);
            userRegReqMap.put(remoteAddr, urr);
        }
        urr.newRequest(emailId);

    }

    private void cleanUserReqMap() {
        ArrayList<UserRegRequest> mapList = new ArrayList<UserRegRequest>();
        for (String key : userRegReqMap.keySet()) {
            mapList.add(userRegReqMap.get(key));
        }
        Collections.sort(mapList);
        Collections.reverse(mapList);

        int i = 0;
        for (UserRegRequest urr : mapList) {
            i++;
            userRegReqMap.remove(urr.getRemoteIp());
            if (i == 700) {
                break;
            }
        }
    }

    private boolean isBlockedIp(Properties prop) throws Exception {
        String remoteAddr = prop.getProperty(REGIS_REQ_REMOTE_IP);
        FileInputStream fis = new FileInputStream(blockedIpListFilePath);
        Properties bipprop = new Properties();
        bipprop.load(fis);
        fis.close();
        return "block".equals(bipprop.getProperty(remoteAddr));
    }

    private void validateCaptchaEntry(Properties prop) throws Exception {
        String remoteAddr = prop.getProperty(REGIS_REQ_REMOTE_IP);
        ReCaptchaImpl reCaptcha = new ReCaptchaImpl();
        reCaptcha.setPrivateKey(captchaPrivateKey);
        String challenge = prop.getProperty(CAPTCHA_CHALLANGE_REQ);
        String uresponse = prop.getProperty(CAPTCHA_CHALLANGE_RESP);

        if (challenge.length() == 0 || uresponse.length() == 0) {
            throw new Exception("Security Validation Failed,Captcha Response Field is empty.");
        }

        ReCaptchaResponse reCaptchaResponse = reCaptcha.checkAnswer(remoteAddr, challenge,
                uresponse);
        if (!reCaptchaResponse.isValid()) {
            throw new Exception(reCaptchaResponse.getErrorMessage());
        }
    }

    private class UserRegRequest implements Comparable<UserRegRequest> {
        private long firstAccessTime = -1;
        private long lastAccessTime = -1;
        private String remoteIp = null;
        private Vector<String> emilList = new Vector<String>();
        private String blockedFilePath = null;

        public UserRegRequest(String remoteIp, String blockedFilePath) {
            this.remoteIp = remoteIp;
            this.blockedFilePath = blockedFilePath;
        }

        public void newRequest(String email) throws Exception {
            emilList.add(email);
            if (firstAccessTime == -1) {
                firstAccessTime = lastAccessTime = System.currentTimeMillis();
            }
            else {
                lastAccessTime = System.currentTimeMillis();
            }
            checkSecurity();
        }

        public String getRemoteIp() {
            return remoteIp;
        }

        public long getLastAccessTime() {
            return lastAccessTime;
        }

        public int compareTo(UserRegRequest obj) {
            long objLastAccessTime = obj.getLastAccessTime();
            return (lastAccessTime > objLastAccessTime ? -1
                    : (lastAccessTime == objLastAccessTime ? 0 : 1));
        }

        private void checkSecurity() throws Exception {
            long timediff = lastAccessTime - firstAccessTime;
            int emaiThreshold = 10;
            int timeThreshold = 30 * 60 * 1000;
            if (emilList.size() > emaiThreshold && timediff < timeThreshold) {
                FileWriter fwriter = null;
                fwriter = new FileWriter(blockedFilePath, true);
                String brecord = remoteIp + "=block";
                fwriter.write(brecord);
                fwriter.close();

                // Print log
                StringBuffer sb = new StringBuffer();
                sb.append("*******IP BLOCKED*******\n");
                sb.append("* blocked ip = " + remoteIp + "\n");
                sb.append("* requested email = ");
                for (String emailId : emilList) {
                    sb.append(emailId + ",");
                }
                sb.append("\n************************");
                System.out.println(sb.toString());
            }
        }
    }

}
