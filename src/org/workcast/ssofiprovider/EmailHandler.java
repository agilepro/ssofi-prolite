package org.workcast.ssofiprovider;

import java.io.File;
import java.io.StringWriter;
import java.net.URLEncoder;
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
import javax.servlet.ServletContext;

import org.workcast.mendocino.Mel;

public class EmailHandler {

    private Vector<String> existingIds = null;
    String overrideAddress;
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

    public EmailHandler(ServletContext sc, Properties props) throws Exception {

        overrideAddress = defProp(props, "overrideAddress", null);
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

        String webInfPath = sc.getRealPath("/WEB-INF");
        profileRequestFile = new File(webInfPath, "profilerequest.xml");

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

    public void sendEmail(String emailId, int reqType, String magicNumber) throws Exception {
        Transport transport = null;
        try {

            /*
            Properties props = new Properties();
            props.put("mail.smtp.auth", smtpAuth);
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.host", smtpHost);
            props.put("mail.smtp.port", smtpPort);
            props.put("mail.smtp.user", smtpUser);
            props.put("mail.smtp.password", smtpPwd);
            */
            String option = "Email Address Confirmation Message";

            Authenticator authenticator = new MyAuthenticator(savedProps);
            Session session = Session.getInstance(savedProps, authenticator);
            session.setDebug(true);
            transport = session.getTransport();
            transport.connect();

            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(smtpFrom));
            if (overrideAddress != null) {
                message.setRecipients(Message.RecipientType.TO,
                        InternetAddress.parse(overrideAddress));
            }
            else {
                message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(emailId));
            }

            message.setSubject(option);

            String registerAddr = OpenIDHandler.baseURL
                    + "?openid.mode=validateKeyAction&registerEmail="
                    + URLEncoder.encode(emailId, "UTF-8") + "&registeredEmailKey="
                    + URLEncoder.encode(magicNumber, "UTF-8");
            StringWriter clone = new StringWriter();
            clone.write("<html><body>\n");
            clone.write("<p>This message was sent to verify your email address: ");
            OpenIDHandler.writeHtml(clone, emailId);
            clone.write(".</p>\n");
            clone.write("<p>Click on <a href=\"");
            OpenIDHandler.writeHtml(clone, registerAddr);
            clone.write("\">this link</a> or copy the following address into your browser:</p>");
            clone.write("<p>");
            OpenIDHandler.writeHtml(clone, registerAddr);
            clone.write("</p>");
            clone.write("<p>Your confirmation key is <b>");
            clone.write(magicNumber);
            clone.write("</b>.  You can enter this in to the confirmation key space on the confirmation page.</p>");
            clone.write("<p>If you did not request this operation, then it is possible");
            clone.write("   that someone else has entered your email by mistake, and you can");
            clone.write("   safely ignore and delete this message.</p>");
            clone.write("</body></html>");

            MimeBodyPart textPart = new MimeBodyPart();
            textPart.setContent(clone.toString(), "text/html;encoding=UTF-8");

            Multipart mp = new MimeMultipart();
            mp.addBodyPart(textPart);
            message.setContent(mp);
            transport.sendMessage(message, message.getAllRecipients());

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
                    + "' in the configuration file for OpenIDServlet");
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

        matcher = pattern.matcher(emailId);
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
