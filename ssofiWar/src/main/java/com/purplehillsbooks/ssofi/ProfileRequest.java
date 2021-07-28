package com.purplehillsbooks.ssofi;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.purplehillsbooks.xml.Mel;

/**
 * An XML element that represents a user
 */
public class ProfileRequest extends Mel {

    public ProfileRequest(Document doc, Element ele) {
        super(doc, ele);
    }

    /**
     * Must be unique within the context that this request is being stored.
     */
    public String getId() {
        return getScalar("id");
    }

    public void setId(String id) {
        setScalar("id", id);
    }

    /**
     * This is a global unique id designed simply to be hard to guess This must
     * be kept secret, never displayed in the user interface, but sent in an
     * email message in order to prove that they got the email message.
     */
    public String getSecurityToken() {
        return getScalar("token");
    }

    public void setSecurityToken(String token) {
        setScalar("token", token);
    }

    public String getEmail() {
        return getScalar("email");
    }

    public void setEmail(String email) {
        setScalar("email", email);
    }

    /**
     * The time that the request was created, for use in timing out the request
     * after a period of time (24 hours).
     */
    public long getTimestamp() {
        // return safeConvertLong(getScalar("timestamp"));
        throw new RuntimeException("should not be calling getTimestamp");
    }

    /**
     * Tells what kind of request it is RESET_PASSWORD = 1; REGISTER_PROFILE =
     * 2;
     */
    public int getReqType() {
        return safeConvertInt(getScalar("type"));
    }

    public void setReqType(int newType) {
        setScalar("type", Integer.toString(newType));
    }

    /**
     * designed primarily for returning date long values works only for positive
     * integer (long) values considers all numeral, ignores all letter and
     * punctuation never throws an exception if you give this something that is
     * not a number, you get surprising result. Zero if no numerals at all.
     */
    public static int safeConvertInt(String val) {
        if (val == null) {
            return 0;
        }
        int res = 0;
        int last = val.length();
        for (int i = 0; i < last; i++) {
            char ch = val.charAt(i);
            if (ch >= '0' && ch <= '9') {
                res = res * 10 + ch - '0';
            }
        }
        return res;
    }

    public static Document createDocument(String rootNodeName) throws Exception {
        DocumentBuilderFactory dfactory = DocumentBuilderFactory.newInstance();
        dfactory.setNamespaceAware(true);
        dfactory.setValidating(false);
        DocumentBuilder bldr = dfactory.newDocumentBuilder();
        Document doc = bldr.newDocument();
        Element rootEle = doc.createElement(rootNodeName);
        doc.appendChild(rootEle);
        return doc;
    }

}
