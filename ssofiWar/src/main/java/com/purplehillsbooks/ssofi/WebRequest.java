package com.purplehillsbooks.ssofi;

import java.io.File;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.URLDecoder;
import java.util.ArrayList;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import com.purplehillsbooks.json.JSONArray;
import com.purplehillsbooks.json.SimpleException;
import com.purplehillsbooks.json.JSONObject;
import com.purplehillsbooks.json.JSONTokener;
import com.purplehillsbooks.streams.StreamHelper;

public class WebRequest {
    public HttpServletRequest  request;
    public HttpServletResponse response;
    public HttpSession         session;
    public OutputStream        outStream;
    public Writer              w;
    public String              requestURL;
    private ArrayList<String>  path;
    private int pathPos = 0;
    private JSONObject postedObject = null;

    public WebRequest (HttpServletRequest _req, HttpServletResponse _resp) throws Exception {
        request = _req;
        response = _resp;
        session = request.getSession();
        setUpForCrossBrowser();
        parsePath();
        outStream = response.getOutputStream();
        w = new OutputStreamWriter(outStream, "UTF-8");
    }

    private void setUpForCrossBrowser() {
        //this is an API to be read by others, so you have to set the CORS to
        //allow scripts to read this data from a browser.
        String origin = request.getHeader("Origin");
        if (origin==null || origin.length()==0) {
            //this does not always work, but what else can we do?
            origin="*";
        }
        response.setHeader("Access-Control-Allow-Origin",      origin);
        response.setHeader("Access-Control-Allow-Credentials", "true");
        response.setHeader("Access-Control-Allow-Methods",     "GET, POST, OPTIONS, PUT");
        response.setHeader("Access-Control-Allow-Headers",     "Origin, X-Requested-With, Content-Type, Accept, Authorization, If-Modified-Since");
        response.setHeader("Access-Control-Max-Age",           "1");
        response.setHeader("Vary",                             "*");

        //default content type is JSON  set it otherwise if you need something different
        response.setContentType("application/json; charset=utf-8");
    }

    /**
     * This is the base URL for the application, which means it has
     * the protocol, server, port, and application name in the path.
     * Everything up to the root of where the application is.
     */
    public String appBaseUrl() {
        int amtToTrim = request.getServletPath().length() + request.getPathInfo().length();
        String appBase = requestURL.substring(0, requestURL.length()-amtToTrim);
        return appBase;
    }

    private void parsePath() throws Exception {
        String ctxtroot = request.getContextPath();
        requestURL = request.getRequestURL().toString();
        int indx = requestURL.indexOf(ctxtroot);
        int start = indx + ctxtroot.length() + 1;

        ArrayList<String> decoded = new ArrayList<String>();
        int pos = requestURL.indexOf("/", start);
        while (pos>=start) {
            addIfNotNull(decoded, requestURL, start, pos);
            start = pos + 1;
            pos = requestURL.indexOf("/", start);
        }
        addIfNotNull(decoded, requestURL, start, requestURL.length());
        path = decoded;
    }

    public String consumePathToken() {
        return path.get(pathPos++);
    }
    public boolean pathFinished() {
        return pathPos >= path.size();
    }

    private void addIfNotNull(ArrayList<String> dest, String source, int start, int pos) throws Exception {
        if (pos<=start) {
            return;
        }
        String token = source.substring(start, pos).trim();
        if (token.length()>0) {
            dest.add(URLDecoder.decode(token, "UTF-8"));
        }
    }

    public boolean isGet() {
        return "get".equalsIgnoreCase(request.getMethod());
    }
    public boolean isPost() {
        return "post".equalsIgnoreCase(request.getMethod());
    }
    public boolean isPut() {
        return "put".equalsIgnoreCase(request.getMethod());
    }
    public boolean isDelete() {
        return "delete".equalsIgnoreCase(request.getMethod());
    }
    public boolean isOptions() {
        return "options".equalsIgnoreCase(request.getMethod());
    }

    public JSONObject getPostedObject() throws Exception {
    	if (isGet()) {
    		return null;
    	}
        if (postedObject!=null) {
            //important to only read the object once!
            return postedObject;
        }
        try {
            InputStream is = request.getInputStream();
            JSONTokener jt = new JSONTokener(is);
            postedObject = new JSONObject(jt);
            is.close();
            return postedObject;
        }
        catch (Exception e) {
            throw new Exception("Failure to read an expected JSON object from the POST stream for this web request: "+requestURL, e);
        }
    }
    String reqParam(String name) throws Exception {

        String val = request.getParameter(name);
        if (val == null || val.length() == 0) {
            throw new SimpleException("Got a request without a required '%s' parameter", name);
        }
        return val;
    }
    String defParam(String name, String defaultVal) throws Exception {

        String val = request.getParameter(name);
        if (val == null || val.length() == 0) {
            return defaultVal;
        }
        return val;
    }

    /**
     * Reads the uploaded PUT body, and stores it to the specified
     * file (using a temp name, and deleting whatever file migth
     * have been there before.)
     */
    public void storeContentsToFile(File destination) throws Exception {
        InputStream is = request.getInputStream();
        StreamHelper.copyStreamToFile(is, destination);
    }

    public void streamJSON(JSONObject jo) throws Exception {
        jo.write(w,2,0);
        w.flush();
    }

    public void streamException(Throwable e) {
        try {
            //all exceptions are delayed by 3 seconds if the duration of the
            //session is less than 3 seconds.
            streamException(e, request, response, w);
        }
        catch (Exception xxx) {
            SimpleException.traceException(xxx, "FATAL EXCEPTION WHILE STREAMING EXCEPTION");
        }

    }
    public static void streamException(Throwable e, HttpServletRequest request,
            HttpServletResponse response, Writer w) {
        try {
            if (w==null) {
                SimpleException.traceException(e, "a null writer object was passed into streamException");
                throw new Exception("a null writer object was passed into streamException");
            }
            if (e==null) {
                throw new Exception("a null exception object was passed into streamException");
            }
            JSONObject responseBody = SimpleException.convertToJSON(e, "Web request for: "+request.getRequestURI());

            //remove the bottom of the stack trace below the HttpServlet.service call
            //because it is all arbitrary garbage below that point and usually quite a lot of noise.
            if (responseBody.has("error")) {
                JSONObject error = responseBody.getJSONObject("error");
                if (error.has("stack")) {
                    JSONArray stack = error.getJSONArray("stack");
                    JSONArray truncStack = new JSONArray();
                    boolean notFound = true;
                    for (int i=0; i<stack.length() && notFound; i++) {
                        String line = stack.getString(i);
                        truncStack.put(line);
                        if (line.contains("HttpServlet") && line.contains("service")) {
                            //this is the last one that will be added
                            notFound = false;
                        }
                    }
                    error.put("stack", truncStack);
                }
            }

            responseBody.put("requestURL", request.getRequestURI());
            //responseBody.put("exceptionTime", Util.currentTimeString());

            response.setContentType("application/json");
            response.setStatus(400);

            SimpleException.traceConvertedException(System.out, responseBody);
            responseBody.write(w, 2, 0);
            w.flush();
        } catch (Exception eeeee) {
            // nothing we can do here...
            SimpleException.traceException(eeeee, "EXCEPTION_WITHIN_EXCEPTION");
        }
    }


    public void streamFile(File fullPath) throws Exception {
        if (!fullPath.exists()) {
            throw new Exception("Program Logic Error: WebRequest.streamFile was asked to stream a file that does not exist: "+fullPath);
        }
        String fileName = fullPath.getName();

        if(fileName.endsWith(".pdf")) {
            //This would allow PDF document to be opened inside browser or PDF viewer
            response.setContentType("application/pdf");
        } else {
            //Actually serve up the file contents here, and this mime type
            //tells the receiver to put the contents into a file without displaying
            response.setContentType("application/octet-stream");
        }

        //It seems that there is no way to get the length of the file
        //from the API.  It really should include in the response header.
        StreamHelper.copyFileToOutput(fullPath, outStream);
    }

    public void streamAttachment(String attachmentName, InputStream content) throws Exception {
        if(attachmentName.endsWith(".pdf")) {
            //This would allow PDF document to be opened inside browser or PDF viewer
            response.setContentType("application/pdf");
        } else {
            //Actually serve up the file contents here, and this mime type
            //tells the receiver to put the contents into a file without displaying
            response.setContentType("application/octet-stream");
        }
        StreamHelper.copyInputToOutput(content, outStream);
    }

    /**
     * proper way to set the session cookie
     * Java Cookie class does not handle SameSite
     * Note: SameSite=None will work only over HTTPS
     * Any test server not using HTTPS will fail to work
     * because the browser will reject it.
     */
    public void setCookieSecure(String name, String sessionId) {
        response.addHeader("Set-Cookie", name+"="+sessionId+";Max-Age=2500000;path=/;SameSite=None;Secure");
    }
    public void setCookie(String name, String sessionId) {
        response.addHeader("Set-Cookie", name+"="+sessionId+";Max-Age=2500000;path=/;SameSite=Lax");
    }

    public String findCookieValue(String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie oneCookie : cookies) {
                if (oneCookie != null) {
                    String cName = oneCookie.getName();
                    if (cName != null && cookieName.equals(cName)) {
                        return oneCookie.getValue();
                    }
                }
            }
        }
        return null;
    }

    public String getSessionAttribute (String key) {
        return (String) session.getAttribute(key);
    }
    public void setSessionAttribute (String key, String value) {
        session.setAttribute(key, value);
    }

}
