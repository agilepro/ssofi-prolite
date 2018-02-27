package com.purplehillsbooks.ssofi;

import java.io.File;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.util.Date;
import java.util.Enumeration;
import java.util.Properties;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.mail.Authenticator;
import javax.mail.Message;
import javax.mail.Multipart;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import com.purplehillsbooks.streams.HTMLWriter;
import com.purplehillsbooks.xml.Mel;

public class EmailHandler {

    private Vector<String> existingIds = null;
    String smtpUser;
    String smtpPwd;
    String protocol;
    String smtpHost;
    String smtpPort;
    String smtpAuth;
    String smtpFrom;
    String mailSub;
    String contentType;
    Properties savedProps;

    public static int RESET_PASSWORD = 1;
    public static int REGISTER_PROFILE = 2;

    static Mel profileRequest;
    static Vector<ProfileRequest> profileRequestList;
    File profileRequestFile;

    private Pattern pattern;
    private Matcher matcher;

    private static final String EMAIL_PATTERN = "^[_A-Za-z0-9-\\+]+(\\.[_A-Za-z0-9-]+)*@"
            + "[A-Za-z0-9-]+(\\.[A-Za-z0-9]+)*(\\.[A-Za-z]{2,})$";

    public EmailHandler(SSOFI ssofi, Properties props) throws Exception {

        smtpUser = requiredProp(props, "mail.smtp.user");
        smtpPwd = requiredProp(props, "mail.smtp.password");
        protocol = defProp(props, "mail.transport.protocol", "smtp");
        smtpHost = requiredProp(props, "mail.smtp.host");
        smtpPort = defProp(props, "mail.smtp.port", "25");
        smtpAuth = requiredProp(props, "mail.smtp.auth");
        smtpFrom = requiredProp(props, "mail.smtp.from");
        mailSub = defProp(props, "mail.subject", "Notification from Openid Provider");
        contentType = defProp(props, "mail.contenttype", "text/html");
        savedProps = props;

        File dataFolder = ssofi.getDataFolder();
        profileRequestFile = new File(dataFolder, "profilerequest.xml");

        if (profileRequestFile.exists()) {
            profileRequest = Mel.readFile(profileRequestFile, Mel.class);
        }
        else {
            profileRequest = Mel.createEmpty("profilerequests", Mel.class);
            profileRequest.writeToFile(profileRequestFile);
        }
        profileRequestList = new Vector<ProfileRequest>();
        profileRequestList.addAll(profileRequest
                .getChildren("profilerequest", ProfileRequest.class));

        pattern = Pattern.compile(EMAIL_PATTERN);
    }

    public void sendVerifyEmail(String emailId, String magicNumber, String app, String baseURL) throws Exception {
        Transport transport = null;
        try {

            String option = "Email Address Confirmation Message";

            Authenticator authenticator = new MyAuthenticator(savedProps);
            Session session = Session.getInstance(savedProps, authenticator);
            //session.setDebug(true);
            transport = session.getTransport();
            transport.connect();

            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(smtpFrom));
            message.setSentDate(new Date());
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(emailId));

            message.setSubject(option);

            String registerAddr = baseURL
                    + "?openid.mode=validateKeyAction&registerEmail="
                    + URLEncoder.encode(emailId, "UTF-8")
                    + "&registeredEmailKey="
                    + URLEncoder.encode(magicNumber, "UTF-8")
		            + "&app="
		            + URLEncoder.encode(app, "UTF-8");
            StringWriter clone = new StringWriter();
            clone.write("<html><body>\n");
            clone.write("<p>This message was sent to verify your email address: <b>");
            HTMLWriter.writeHtml(clone, emailId);
            clone.write("</b>.</p>\n");
            clone.write("<p>Click to <a href=\"");
            HTMLWriter.writeHtml(clone, registerAddr);
            clone.write("\"><b>SET YOUR PASSWORD</b></a>.</p>");
            clone.write("<p></p>");
            clone.write("<p>(Note: You must use the link within 7 days of ");
            clone.write("receiving the email, and you can only use the link once.  ");
            clone.write("If you don't know who this message is from, and you are not ");
            clone.write("aware of the project you can safely ignore this message. ");
            clone.write("Someone may have entered your address by accident.)</p>");
            clone.write("</body></html>");

            MimeBodyPart textPart = new MimeBodyPart();
            textPart.setContent(clone.toString(), "text/html;encoding=UTF-8");

            Multipart mp = new MimeMultipart();
            mp.addBodyPart(textPart);
            message.setContent(mp);
            transport.sendMessage(message, message.getAllRecipients());

            System.out.println("SSOFI: Email verification request sent to: "+emailId);
        }
        catch (Exception e) {
            throw new RuntimeException("Unable to send an email message for (" + emailId + ")", e);
        } finally {
            if (transport != null) {
                try {
                    transport.close();
                } catch (Exception ce) { /* ignore this exception */
                }
            }
        }
    }

    public void sendInviteEmail(String fromEmail, String fromName, String emailId, String body, String magicNumber,
            String app, String baseURL) throws Exception {
        Transport transport = null;
        try {

            String subject = "Invitation to Collaborate";

            Authenticator authenticator = new MyAuthenticator(savedProps);
            Session session = Session.getInstance(savedProps, authenticator);
            //session.setDebug(true);
            transport = session.getTransport();
            transport.connect();

            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(fromEmail, fromName));
            message.setSentDate(new Date());
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(emailId));

            message.setSubject(subject);

            String registerAddr = baseURL
                    + "?openid.mode=validateKeyAction&registerEmail="
                    + URLEncoder.encode(emailId, "UTF-8")
                    + "&registeredEmailKey="
                    + URLEncoder.encode(magicNumber, "UTF-8")
		            + "&app="
		            + URLEncoder.encode(app, "UTF-8");
            StringWriter clone = new StringWriter();
            clone.write("<html><body>\n");
            clone.write("<p>");
            HTMLWriter.writeHtmlWithLines(clone, body);
            clone.write("</p>\n");
            clone.write("<p>Click to <a href=\"");
            HTMLWriter.writeHtml(clone, registerAddr);
            clone.write("\"><b>SET YOUR PASSWORD</b></a>.</p>");
            clone.write("<p></p>");
            clone.write("<p>(Note: You must use the link within 7 days of ");
            clone.write("receiving the email, and you can only use the link once.  ");
            clone.write("If you don't know who this message is from, and you are not ");
            clone.write("aware of the project you can safely ignore this message. ");
            clone.write("Someone may have entered your address by accident.)</p>");
            clone.write("</body></html>");

            MimeBodyPart textPart = new MimeBodyPart();
            textPart.setContent(clone.toString(), "text/html;encoding=UTF-8");

            Multipart mp = new MimeMultipart();
            mp.addBodyPart(textPart);
            message.setContent(mp);
            transport.sendMessage(message, message.getAllRecipients());
            
            System.out.println("SSOFI: Invitation sent to: "+emailId);

        }
        catch (Exception e) {
            throw new RuntimeException("Unable to send an email message for (" + emailId + ")", e);
        } finally {
            if (transport != null) {
                try {
                    transport.close();
                } catch (Exception ce) { /* ignore this exception */
                }
            }
        }
    }

    private static String defProp(Properties props, String key, String defVal) throws Exception {
        String val = props.getProperty(key);
        if (val == null) {
            return defVal;
        }
        return val;
    }

    private static String requiredProp(Properties props, String key) throws Exception {
        String val = props.getProperty(key);
        if (val == null) {
            throw new Exception("Must have a setting for '" + key
                    + "' in the email configuration file");
        }
        return val;
    }

    private String createMagicNumber(String fourNumberId) throws Exception {
        String nineLetters = IdGenerator.generateKey();
        StringBuffer betterNumber = new StringBuffer(20);
        betterNumber.append(nineLetters.substring(0, 3));
        betterNumber.append("-");
        betterNumber.append(fourNumberId.substring(0, 2));
        betterNumber.append("-");
        betterNumber.append(nineLetters.substring(3, 6));
        betterNumber.append("-");
        betterNumber.append(fourNumberId.substring(2, 4));
        betterNumber.append("-");
        betterNumber.append(nineLetters.substring(6, 9));
        return betterNumber.toString();
    }

    /**
     * Get a four digit numeric id which is unique on the page.
     */
    public String getUniqueOnPage() throws Exception {
        if (existingIds == null) {
            existingIds = new Vector<String>();
        }
        return IdGenerator.generateFourDigit(existingIds);
    }

    public ProfileRequest createProfileRequest(int requestType, String email, long nowTime)
            throws Exception {

        Mel newChild = profileRequest.addChild("profilerequest", Mel.class);
        String uniqueId = getUniqueOnPage();
        newChild.setScalar("id", uniqueId);
        newChild.setScalar("email", email);
        newChild.setScalar("type", Integer.toString(requestType));
        newChild.setScalar("token", createMagicNumber(uniqueId));
        saveProfReqFile(newChild);
        refreshProfReqList();
        ProfileRequest profRequest = findProfReqOrNull(uniqueId);
        return profRequest;
    }

    public static String getPromptString(int type) throws Exception {
        if (type == RESET_PASSWORD) {
            return "Reset Password";
        }
        if (type == REGISTER_PROFILE) {
            return "Register New Email";
        }
        else {
            return "Register New Email";
        }
    }

    public ProfileRequest findProfReqOrNull(String id) {

        ProfileRequest recentProfReq = null;
        for (ProfileRequest oneProfReq : profileRequestList) {
            if (oneProfReq.getId().equals(id)) {
                // return oneProfReq;
                if (recentProfReq != null) {
                    if (recentProfReq.getTimestamp() < oneProfReq.getTimestamp()) {
                        recentProfReq = oneProfReq;
                    }
                }
                else {
                    recentProfReq = oneProfReq;
                }
            }
        }
        return recentProfReq;
    }

    public ProfileRequest findProfReqByEmailId(String emailId) {

        ProfileRequest recentProfReq = null;
        for (ProfileRequest oneProfReq : profileRequestList) {
            if (oneProfReq.getEmail().equalsIgnoreCase(emailId)) {
                // return oneProfReq;
                if (recentProfReq != null) {
                    if (recentProfReq.getTimestamp() < oneProfReq.getTimestamp()) {
                        recentProfReq = oneProfReq;
                    }
                }
                else {
                    recentProfReq = oneProfReq;
                }
            }
        }
        return recentProfReq;
    }

    public void removeProfileRequest(String id) throws Exception {
        Vector<ProfileRequest> nl = profileRequest.getChildren("profilerequest",
                ProfileRequest.class);
        Enumeration<ProfileRequest> en = nl.elements();
        while (en.hasMoreElements()) {
            ProfileRequest tEle = en.nextElement();
            if (id.equals(tEle.getAttribute("id"))) {
                profileRequest.removeChild(tEle);
            }
        }
        saveProfReqFile(profileRequest);
        refreshProfReqList();
    }

    public void refreshProfReqList() throws Exception {
        profileRequest = Mel.readFile(profileRequestFile, Mel.class);
        profileRequestList.removeAllElements();
        profileRequestList.addAll(profileRequest
                .getChildren("profilerequest", ProfileRequest.class));
    }

    private void saveProfReqFile(Mel newProfReq) throws Exception {

        newProfReq.reformatXML();
        newProfReq.writeToFile(profileRequestFile);
    }

    public boolean validate(final String emailId) {

        matcher = pattern.matcher(emailId.trim());
        return matcher.matches();

    }

    /**
     * A simple authenticator class that gets the username and password
     * from the properties object if mail.smtp.auth is set to true.
     *
     * documentation on javax.mail.Authenticator says that if you want
     * authentication, return an object, otherwise return null.  So
     * null is returned if no auth setting or user/password.
     */
    private static class MyAuthenticator extends javax.mail.Authenticator {
        private Properties props;

        public MyAuthenticator(Properties _props) {
            props = _props;
        }

        protected PasswordAuthentication getPasswordAuthentication() {
            if ("true".equals(props.getProperty("mail.smtp.auth"))) {
                return new PasswordAuthentication(
                        props.getProperty("mail.smtp.user"),
                        props.getProperty("mail.smtp.password"));
            }
            return null;
        }
    }


}
