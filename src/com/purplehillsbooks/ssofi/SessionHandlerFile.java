package com.purplehillsbooks.ssofi;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

/**
 * This saves the sessions in files in a folder
 */
public class SessionHandlerFile {
    private File sessionFolder;
    private SSOFI ssofi;

    /**
     * This is the limit, in seconds, on how old a session can be.
     * Throw away any session after this many seconds since authentication.
     * This is detected by the file timestamp of the file that holds the
     * session information.  Every log in must write the file again, causing
     * the timestamp to update.  That is the time of the last login.
     * Once you exceed this time limit, user is forced to log in again.
     * Time limit policy is set by the config file and that is the
     * MAXIMUM time limit.  Some users may choose shorter limits.
     */
    long timeLimit;

    public SessionHandlerFile(File mainFolder, long _timeLimit, SSOFI _ssofi) throws Exception {
        ssofi = _ssofi;
        try {
            timeLimit = _timeLimit;
            if (!mainFolder.exists()) {
                throw new Exception("SessionFolder does not exist or the system user does not have access to it.");
            }
            sessionFolder = mainFolder;
            if (!mainFolder.isDirectory()) {
                throw new Exception("SessionFolder appears to be a file or something other than a folder/directory.");
            }
            if (!sessionFolder.canRead()) {
                throw new Exception("SessionFolder is not readable by the server.");
            }
            if (!sessionFolder.canWrite()) {
                throw new Exception("SessionFolder is not writeable by the server.");
            }

            File[] children = sessionFolder.listFiles();
            if (children==null) {
                throw new Exception("Unknown problem.  OS returned null for children.  "
                            +"Does the system user have access to the SessionFolder?");
            }

            // clean out old files
            long oldestTimeStampAllowed = System.currentTimeMillis() - (timeLimit*1000);
            for (File child : children) {
                if (child.lastModified() < oldestTimeStampAllowed) {
                    if (child.getName().endsWith(".sess")) {
                        child.delete();
                    }
                    if (child.getName().endsWith(".$temp")) {
                        child.delete();
                    }
                }
            }

        }
        catch (Exception e) {
            throw new Exception("Unable to initialize the SessionFolder ("+mainFolder+").", e);
        }

        System.out.println("SSOFI: Using the FILE session handler: "+mainFolder);
    }

    /**
     * pass in the session id, and get the session information back
     */
    public synchronized AuthSession getAuthSession(WebRequest wr, String sessionId) throws Exception {
        long oldestTimeStampAllowed = System.currentTimeMillis() - (timeLimit*1000);
        File sessionFile = new File(sessionFolder, sessionId + ".sess");
        try {
            AuthSession as = null;
            if (sessionFile.exists()) {
                if (sessionFile.lastModified() < oldestTimeStampAllowed) {
                    // timestamp is too old, so remove the file
                    sessionFile.delete();
                }
                else {
                    FileInputStream fileIn = new FileInputStream(sessionFile);
                    ObjectInputStream in = new ObjectInputStream(fileIn);
                    as = (AuthSession) in.readObject();
                    in.close();
                    fileIn.close();
                    //migration for files that did not have the session id yet
                    as.sessionId = sessionId;
                }
            }
            if (as == null) {
                //since we did not find an existing session, destroy that ID and generate
                //another one for a brand new session.   This helps rotate sessions ids
                //frequently, and harder to steal.
                sessionId = ssofi.createSSOFISessionId(wr);
                as = new AuthSession(sessionId);
                saveAuthSession(sessionId, as);
            }
            if (as.presumedId == null ||  as.presumedId.length()==0) {
                //if the session does not have an assumed user id in it, then
                //get the last good ID from the cookie.
                as.presumedId = wr.findCookieValue("SSOFIUser");
            }

            return as;
        }
        catch (Exception e) {
            throw new Exception("Failure trying to read the session file: "+sessionFile, e);
        }
    }

    public synchronized void saveAuthSession(String sessionId, AuthSession thisSession)
            throws Exception {

        //this is to assure that the session ID is included for bigration cases
        //and that it is the same as the file that is being stored.
        thisSession.sessionId = sessionId;

        File sessionFile = new File(sessionFolder, sessionId + ".sess");
        File tempFile = new File(sessionFolder, sessionId + System.currentTimeMillis() + ".$temp");
        FileOutputStream fileOut = new FileOutputStream(tempFile);
        ObjectOutputStream out = new ObjectOutputStream(fileOut);
        out.writeObject(thisSession);
        out.close();
        fileOut.close();
        // now swap the names
        if (sessionFile.exists()) {
            sessionFile.delete();
        }
        if (sessionFile.exists()) {
            System.out.println("SSOFI: Failed 1st time to delete " + sessionFile);
            sessionFile.delete();
        }
        if (!tempFile.renameTo(sessionFile)) {
            System.out.println("SSOFI: Failed 1st time to rename " + tempFile);
            if (!tempFile.renameTo(sessionFile)) {
                System.out.println("SSOFI: Failed 2nd time to rename " + tempFile);
            }
        }
        if (tempFile.exists()) {
            System.out.println("SSOFI: Temp file remains " + tempFile);
        }
    }

    public synchronized void deleteAuthSession(String sessionId) throws Exception {
        File sessionFile = new File(sessionFolder, sessionId + ".sess");
        if (sessionFile.exists()) {
            sessionFile.delete();
        }
    }


}
