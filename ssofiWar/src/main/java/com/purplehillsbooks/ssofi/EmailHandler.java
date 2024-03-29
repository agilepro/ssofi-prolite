package com.purplehillsbooks.ssofi;

import java.io.File;
import java.io.Writer;
import java.net.URLEncoder;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import jakarta.mail.Authenticator;
import jakarta.mail.Message;
import jakarta.mail.Multipart;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;

import com.purplehillsbooks.json.SimpleException;
import com.purplehillsbooks.streams.HTMLWriter;
import com.purplehillsbooks.streams.MemFile;
import com.purplehillsbooks.xml.Mel;

public class EmailHandler {

    private ArrayList<String> existingIds = null;
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
    static ArrayList<ProfileRequest> profileRequestList;
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
        profileRequestList = new ArrayList<ProfileRequest>();
        profileRequestList.addAll(profileRequest
                .getChildren("profilerequest", ProfileRequest.class));

        pattern = Pattern.compile(EMAIL_PATTERN);

        System.out.println("SSOFI: Email configured: "+smtpHost+":"+smtpPort+":"+smtpUser+" at "+AuthSession.currentTimeString());
    }

    public void sendVerifyEmail(String emailId, String magicNumber, String app, String baseURL) throws Exception {
        Transport transport = null;
        try {
            long currentTime = System.currentTimeMillis();
            long timeOutTime = currentTime + 7L * 24 * 60 * 60000;

            String option = "Email Address Confirmation Message";
            if (app == null) {
                app = "";
            }

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
            MemFile mf = new MemFile();
            Writer clone = mf.getWriter();
            clone.write("<html><body>\n");
            clone.write("<p>This message was sent to verify your email address: <b>");
            HTMLWriter.writeHtml(clone, emailId);
            clone.write("</b>.</p>\n");
            clone.write("<p>Click to <a href=\"");
            HTMLWriter.writeHtml(clone, registerAddr);
            clone.write("\"><b>SET YOUR PASSWORD</b></a>.</p>");
            clone.write("<p></p>");
            clone.write("<p>(Note: This email was sent at ");
            clone.write(getFormattedDate(currentTime));
            clone.write(" on the server, you must use the link before ");
            clone.write(getFormattedDate(timeOutTime));
            clone.write(", and you can only use the link once.  \n");
            clone.write("You can request a new link from the server.  \n");
            clone.write("If you did not request this password reset email you can safely ignore this message. ");
            clone.write("Someone may have entered your address by accident.)</p>\n");
            clone.write("</body></html>");
            clone.flush();

            MimeBodyPart textPart = new MimeBodyPart();
            textPart.setText(mf.toString(), "UTF-8", "html");

            Multipart mp = new MimeMultipart();
            mp.addBodyPart(textPart);
            message.setContent(mp);
            transport.sendMessage(message, message.getAllRecipients());

            System.out.println("SSOFI-EMAIL: Password reset email sent to: "+emailId
                     +" at "+AuthSession.currentTimeString());
        }
        catch (Exception e) {
            throw new RuntimeException("Unable to send an email message for (" + emailId + ") at "+AuthSession.currentTimeString(), e);
        } finally {
            if (transport != null) {
                try {
                    transport.close();
                } catch (Exception ce) { /* ignore this exception */
                }
            }
        }
    }

    public void sendInviteEmail(String fromName, String emailId, 
            String body, String subject, String magicNumber,
            String app, String baseURL) throws Exception {
        Transport transport = null;
        try {
            
            long currentTime = System.currentTimeMillis();
            long timeOutTime = currentTime + 7L * 24 * 60 * 60000;

            Authenticator authenticator = new MyAuthenticator(savedProps);
            Session session = Session.getInstance(savedProps, authenticator);
            //session.setDebug(true);
            transport = session.getTransport();
            transport.connect();

            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(smtpFrom, fromName));
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
            
            
            MemFile mf = new MemFile();
            Writer clone = mf.getWriter();
            clone.write("<html><body>\n");
            clone.write("<p>");
            HTMLWriter.writeHtmlWithLines(clone, body);
            clone.write("</p>\n<hr/>\n");
            clone.write("<p>You will need to authenticate.  ");
            clone.write("If you have not set up a password, or you have ");
            clone.write("forgotten your password, then you can use this convenient ");
            clone.write("link to set your password for the site.</p>\n\n");
            clone.write("<p>Click to <a href=\"");
            HTMLWriter.writeHtml(clone, registerAddr);
            clone.write("\"><b>SET YOUR PASSWORD</b></a>.</p>");
            clone.write("<p>If you have already set up a password for ");
            HTMLWriter.writeHtml(clone, emailId);
            clone.write(" and logged in, then you can access the site immediately:</p>\n\n");
            clone.write("<p>Click to <a href=\"");
            HTMLWriter.writeHtml(clone, app);
            clone.write("\"><b>ACCESS SITE DIRECTLY</b></a>.</p>\n\n");
            clone.write("<p></p>");
            clone.write("<p>(Note: This email was sent at ");
            clone.write(getFormattedDate(currentTime));
            clone.write(" on the server, you must use the link before ");
            clone.write(getFormattedDate(timeOutTime));
            clone.write(", and you can only use the link once.  \n");
            clone.write("You can request a new link from the server.  \n");
            clone.write("If you don't know who sent this message, and you are not ");
            clone.write("aware of the application mentioned, you can safely ignore this message. ");
            clone.write("Someone may have entered your address by accident.)</p>\n");
            clone.write("</body></html>");
            clone.flush();

            MimeBodyPart textPart = new MimeBodyPart();
            textPart.setText(mf.toString(), "UTF-8", "html");

            Multipart mp = new MimeMultipart();
            mp.addBodyPart(textPart);
            message.setContent(mp);
            transport.sendMessage(message, message.getAllRecipients());
            
            System.out.println("SSOFI-EMAIL: Invitation sent to: "+emailId+" at "+AuthSession.currentTimeString());

        }
        catch (Exception e) {
            throw new RuntimeException("Unable to send an email message for (" + emailId + ") at "+AuthSession.currentTimeString(), e);
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
            throw new SimpleException("Must have a setting for '%s' in the email configuration file", key);
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
            existingIds = new ArrayList<String>();
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
        List<ProfileRequest> nl = profileRequest.getChildren("profilerequest",
                ProfileRequest.class);
        for (ProfileRequest tEle : nl) {
            if (id.equals(tEle.getAttribute("id"))) {
                profileRequest.removeChild(tEle);
            }
        }
        saveProfReqFile(profileRequest);
        refreshProfReqList();
    }

    public void refreshProfReqList() throws Exception {
        profileRequest = Mel.readFile(profileRequestFile, Mel.class);
        profileRequestList.clear();
        profileRequestList.addAll(profileRequest
                .getChildren("profilerequest", ProfileRequest.class));
    }

    private void saveProfReqFile(Mel newProfReq) throws Exception {

        newProfReq.reformatXML();
        newProfReq.writeToFile(profileRequestFile);
    }

    public boolean validAddressFormat(final String emailId) {

        matcher = pattern.matcher(emailId.trim());
        return matcher.matches();

    }

    /**
     * A simple authenticator class that gets the username and password
     * from the properties object if mail.smtp.auth is set to true.
     *
     * documentation on jakarta.mail.Authenticator says that if you want
     * authentication, return an object, otherwise return null.  So
     * null is returned if no auth setting or user/password.
     */
    private static class MyAuthenticator extends jakarta.mail.Authenticator {
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

    private static DateFormat df = new SimpleDateFormat("dd-MMM-YYYY HH:mm");
    private String getFormattedDate(long time) {
        Date date = new Date(time);
        return df.format(date);
    }

}
