package com.purplehillsbooks.ssofi;

import java.util.Vector;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.purplehillsbooks.xml.Mel;

/**
 * An XML element that represents a user
 */
public class User extends Mel {
    
    //this is the last half of unique key for users, set every server start
    //this arbitrary value is based on the server mac address,  must be 
    //initialized by SSOFI init.
    public static String guidTail;

    public User(Document doc, Element ele) {
        super(doc, ele);
        
        //schema migration, add key in if not already there
        String key = getKey();
        if (key==null || key.length()==0) {
        	setKey(generateKey());
        }
    }

    public boolean hasEmail(String specAddr) {
        for (String addr : getVector("address")) {
            if (addr.equalsIgnoreCase(specAddr)) {
                return true;
            }
        }
        return false;
    }

    public boolean hasEmailMatchingSearchTerm(String searchTerm) {
        for (String addr : getVector("address")) {
            if (addr.indexOf(searchTerm) >= 0) {
                return true;
            }
        }
        return false;
    }

    public String getEmailMatchingSearchTerm(String searchTerm) {
        for (String addr : getVector("address")) {
            // for surity changing email id and searchterm both to lower case
            if (addr.toLowerCase().indexOf(searchTerm.toLowerCase()) >= 0) {
                return addr;
            }

        }
        return null;
    }

    public Vector<String> getAddresses() {
        return getVector("address");
    }

    public void addAddress(String newAddress) throws Exception {
        for (Mel oneAddr : getChildren("address")) {
            if (newAddress.equalsIgnoreCase(oneAddr.getDataValue())) {
            	//already there, so don't add anything
                return;
            }
        }
        addVectorValue("address", newAddress);
    }

    public void removeAddress(String oldAddress) throws Exception {
    	if (oldAddress==null) {
    		throw new Exception("Program Logic Error: null address passed to removeAddress");
    	}
        for (Mel oneAddr : getChildren("address")) {
            if (oldAddress.equalsIgnoreCase(oneAddr.getDataValue())) {
                removeChild(oneAddr);
                return;
            }
        }
    }

    public String getPassword() {
        return getScalar("password");
    }

    public void setPassword(String password) {
        setScalar("password", password);
    }

    public String getKey() {
        return getScalar("key");
    }

    public void setKey(String key) {
        setScalar("key", key);
    }

    public boolean getAdmin() {
        return "true".equals(getScalar("admin"));
    }

    public void setAdmin(boolean isTrue) {
        if (isTrue) {
            setScalar("admin", "true");
        }
        else {
            setScalar("admin", "false");
        }
    }

    public String getFullName() {
        return getScalar("fullname");
    }

    public void setFullName(String newName) {
        setScalar("fullname", newName);
    }
    
    private static long lastKey = 0;
    private static char[] thirtySix = new char[] {'a','b','c','d','e','f','g',
    	'h','i','j', 'k','l','m','n','o','p','q','r','s','t','u','v','w',
    	'x','y','z','0','1','2','3','4','5','6','7','8','9'};
    /**
    * Generates a value based on the current time, but checking
    * that it has not given out this value before.  If a key has
    * already been given out for the current time, it increments
    * by one.  This method works as long as on the average you
    * get less than one ID per second.
    */
    public synchronized static String generateKey() {
        long ctime = System.currentTimeMillis()/1000;
        if (ctime <= lastKey) {
            ctime = lastKey+1;
        }
        lastKey = ctime;

        //now convert timestamp into cryptic alpha string
        //start with the server defined prefix based on mac address
        StringBuffer res = new StringBuffer(8);
        while (ctime>0) {
            res.append(thirtySix[(int)ctime % 36]);
            ctime = ctime / 36;
        }
        res.append(guidTail);
        return res.toString();
    }
}
