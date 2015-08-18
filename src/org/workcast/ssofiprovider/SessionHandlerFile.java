package org.workcast.ssofiprovider;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

/**
 * This saves the sessions in files in a folder
 */
public class SessionHandlerFile implements SessionHandler {
    File folder;

    public SessionHandlerFile(File mainFolder) throws Exception {
        if (!mainFolder.exists()) {
            throw new Exception("SessionFolder does not exist (" + mainFolder.toString() + ")");
        }
        folder = mainFolder;

        // clean out old files
        long oneHourAgo = System.currentTimeMillis() - 3600000;
        for (File child : folder.listFiles()) {
            if (child.lastModified() < oneHourAgo) {
                if (child.getName().endsWith(".session")) {
                    child.delete();
                }
                if (child.getName().endsWith(".$temp")) {
                    child.delete();
                }
            }
        }
    }

    /**
     * pass in the session id, and get the session information back
     */
    public synchronized AuthSession getAuthSession(String sessionId) throws Exception {
        long oneHourAgo = System.currentTimeMillis() - 3600000;
        File sessionFile = new File(folder, sessionId + ".session");
        AuthSession as = null;
        if (sessionFile.exists()) {
            if (oneHourAgo < sessionFile.lastModified()) {
                FileInputStream fileIn = new FileInputStream(sessionFile);
                ObjectInputStream in = new ObjectInputStream(fileIn);
                as = (AuthSession) in.readObject();
                in.close();
                fileIn.close();
            }
            else {
                // timestamp is too old, so remove the file
                sessionFile.delete();
            }
        }
        if (as == null) {
            as = new AuthSession();
        }
        return as;
    }

    public synchronized void saveAuthSession(String sessionId, AuthSession thisSession)
            throws Exception {

        File sessionFile = new File(folder, sessionId + ".session");
        File tempFile = new File(folder, sessionId + System.currentTimeMillis() + ".$temp");
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
            System.out.println("Failed 1st time to delete " + sessionFile);
            sessionFile.delete();
        }
        if (!tempFile.renameTo(sessionFile)) {
            System.out.println("Failed 1st time to rename " + tempFile);
            if (!tempFile.renameTo(sessionFile)) {
                System.out.println("Failed 2nd time to rename " + tempFile);
            }
        }
        if (tempFile.exists()) {
            System.out.println("Temp file remains " + tempFile);
        }
    }

    /**
     * call this to indicate that the session has been accessed, and to set the
     * timestamp to the current time.
     */
    public synchronized void markSessionTime(String sessionId) throws Exception {
        File sessionFile = new File(folder, sessionId + ".session");
        sessionFile.setLastModified(System.currentTimeMillis());
    }

}
