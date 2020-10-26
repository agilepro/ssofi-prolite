package com.purplehillsbooks.ssofi;

import java.io.File;

import com.purplehillsbooks.json.JSONException;

/**
 * This saves the sessions in files in a folder
 */
public class SessionHandlerFile {
    private File sessionFolder;

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

    public SessionHandlerFile(File mainFolder, long _timeLimit) throws Exception {
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
            cleanOutOldSessions();
        }
        catch (Exception e) {
            throw new Exception("Unable to initialize the SessionFolder ("+mainFolder+").", e);
        }

        System.out.println("SSOFI: Using the FILE session handler: "+mainFolder);
    }

    static long nextTimeToCheck = 0;

    public void cleanOutOldSessions() throws Exception {
        if (System.currentTimeMillis()<nextTimeToCheck) {
            //avoid checking more than every 30 seconds
            return;
        }
        long oldestTimeStampAllowed = System.currentTimeMillis() - (timeLimit*1000);
        File[] children = sessionFolder.listFiles();
        if (children==null) {
            throw new Exception("Unknown problem.  OS returned null for children.  "
                        +"Does the system user have access to the SessionFolder?");
        }
        for (File child : children) {
            if (child.lastModified() < oldestTimeStampAllowed) {
                if (child.getName().endsWith(".ss")) {
                    child.delete();
                }
                if (child.getName().endsWith(".sess")) {
                    child.delete();
                }
                if (child.getName().endsWith(".$temp")) {
                    child.delete();
                }
            }
        }
        //don't check for another 30 seconds
        nextTimeToCheck = System.currentTimeMillis()+30000;
    }
    /**
     * pass in the session id, and get the session information back
     */
    public synchronized AuthSession getAuthSession(WebRequest wr, String sessionId) throws Exception {

        try {
            cleanOutOldSessions();
            AuthSession as = AuthSession.readOrCreateSessionFile(sessionFolder, sessionId);
            if (as.presumedId == null ||  as.presumedId.length()==0) {
                //if the session does not have an assumed user id in it, then
                //get the last good ID from the cookie.
                as.presumedId = wr.findCookieValue("SSOFIUser");
            }

            return as;
        }
        catch (Exception e) {
            JSONException.traceException(e, "Failure loading session file for sessionId="+sessionId);
            AuthSession as2 = new AuthSession(SSOFI.createSSOFISessionId(wr));
            return as2;
        }
    }

    public synchronized void saveAuthSession(AuthSession thisSession) throws Exception {
        thisSession.writeSessionToFile(sessionFolder);
    }

    public synchronized void deleteAuthSession(String sessionId) throws Exception {
        File sessionFile = new File(sessionFolder, sessionId + ".ss");
        if (sessionFile.exists()) {
            sessionFile.delete();
        }
    }


}
