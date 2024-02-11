package com.purplehillsbooks.ssofi;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.purplehillsbooks.json.JSONArray;
import com.purplehillsbooks.json.JSONException;
import com.purplehillsbooks.json.JSONObject;

/**
 * This servlet serves up data using the following base URL:
 *
 * http://{machine:port}/{application}/rest/    ==   {baseurl}
 *
 * The details of course depends upon the host and how to install
 * the application server.  All of that is represented by the
 * symbol {baseurl} for all the discussion below.
 *
 */

@SuppressWarnings("serial")
public class RestServlet extends jakarta.servlet.http.HttpServlet {

    /**
     * If initError is null, it means it was initialized correctly.
     * If it is not null, then something happened during initialization
     * and it is NOT properly initialized.  Every request will then
     * simply return the init error as JSON object.
     *
     * This gives you only one chance to init.  We need a mechanism that
     * retries init in a turtle-model, but that not implemented.
     */
    private Exception initError;

    @Override
    public void init(ServletConfig config) throws ServletException {
        try {
            RestHandler.init(config);
        }
        catch (Exception e) {
            initError = new ServletException("Unable to initialize RestServlet", e);
        }
    }


    @Override
    public void destroy() {
    }

    @Override
    public void service(HttpServletRequest req, HttpServletResponse resp) {
        long startTime = System.currentTimeMillis();
        WebRequest wr;
        RestHandler rh;
        try {
            File webInfFolder = new File(req.getServletContext().getRealPath("/WEB-INF"));
            if (!webInfFolder.exists()) {
                System.out.println("At 'service' the ServletContext reported invalid WEB-INF location:  "+webInfFolder);
            }
            //first handle case where initialization failed
            if (initError!=null) {
                resp.setStatus(400);
                WebRequest.streamException(initError, req, resp, resp.getWriter());
                return;
            }

            wr = new WebRequest(req, resp);
            rh = new RestHandler(wr);
        }
        catch (Exception nonReturnable) {
            //if this fails, then it is a failure communicating to the client
            //and we can not return an error to them, so simply report to the
            //server log file and give up.
            System.out.println("SSOFI-FATAL-ERROR:"+nonReturnable.toString());
            JSONException.traceException(nonReturnable, "RestServlet.service");
            resp.setStatus(501);
            return;
        }
        try {
            if (wr.isOptions()) {
                //this is the CORS 'preflight' option getting headers before sending the
                //actual object.  An option request should not cause the server to access
                //data or burden it in any way, so handled here regardless of the path.
                //Return all the normal headers, but an empty body.
                wr.response.setContentLength(0);
                wr.w.flush();
                System.out.println("SSOFI-OPTIONS,"+startTime+",0,"+req.getContextPath());
                return;
            }
            else {
                JSONObject outObj = rh.handleRequest();
                if (outObj!=null) {
                    outObj.write(wr.w,2,0);
                    wr.w.flush();
                }
            }
        }
        catch (Throwable e) {
            //NOTE: need to catch Throwable here because an Error (such as class not found)
            //would otherwise result in an HTML error message being returned, and not a JSON error.
            //This makes sure that anything that is thrown returns a JSON.
            //
            //Controversial because this might be something critical and the server might not
            //be stable enough to return the result, and trying to return a result might make
            //things worse.   But then, if things are really so bad, who cares?
            System.out.println("SSOFI-HANDLER-ERROR:"+e.toString());
            wr.streamException(e);
            JSONException.traceException(e, "SSOFI RestServlet root level exception catcher");
        }
        long endTime = System.currentTimeMillis();
        long dur = endTime - startTime;
        System.out.println("AA-"+req.getMethod()+","+startTime+","+dur+","+wr.requestURL);
    }



    /**
     * this converts to JSON and includes some special rules for IBPM Model exceptions
     */
    public static JSONObject convertModelExceptionToJSON(Throwable e, String context) throws Exception {
        JSONObject responseBody = new JSONObject();
        JSONObject errorTag = new JSONObject();
        responseBody.put("error", errorTag);

        errorTag.put("code", 400);
        errorTag.put("context", context);

        JSONArray detailList = new JSONArray();
        errorTag.put("details", detailList);

        String lastMessage = "";

        Throwable nextRunner = e;
        List<ExceptionTracer> traceHolder = new ArrayList<ExceptionTracer>();
        while (nextRunner!=null) {
            //doing this at the top allows 'continues' statements to be safe
            Throwable runner = nextRunner;
            nextRunner = runner.getCause();

            String className =  runner.getClass().getName();
            String msg =  runner.toString();

            //iflow has this annoying habit of including all the later causes in the response
            //surrounded by braces.  This strips them off because we are going to iterate down
            //to those causes anyway.
            boolean isIFlow = className.indexOf("iflow")>0;
            if (isIFlow) {
                int bracePos = msg.indexOf('{');
                if (bracePos>0) {
                    msg = msg.substring(0,bracePos);
                }
            }

            if (msg.startsWith(className) && msg.length()>className.length()+5) {
                int skipTo = className.length();
                while (skipTo<msg.length()) {
                    char ch = msg.charAt(skipTo);
                    if (ch != ':' && ch != ' ') {
                        break;
                    }
                    skipTo++;
                }
                msg = msg.substring(skipTo);
            }

            if (lastMessage.equals(msg)) {
                //model api has an incredibly stupid pattern of catching an exception, and then throwing a
                //new exception with the exact same message.  This ends up in three or four duplicate messages.
                //Check here for that problem, and eliminate duplicate messages by skipping rest of loop.
                continue;
            }

            ExceptionTracer et = new ExceptionTracer();
            et.t = runner;
            et.msg = msg;
            et.captureTrace();
            traceHolder.add(et);

            lastMessage = msg;

            JSONObject detailObj = new JSONObject();
            if (runner instanceof JSONException) {
                JSONException jrun = (JSONException)runner;
                if (jrun.params.length>0) {
                    detailObj.put("template", jrun.template);
                    for (int i=0; i<jrun.params.length; i++) {
                        detailObj.put("param"+i,jrun.params[i]);
                    }
                }
            }
            detailObj.put("message",msg);
            int dotPos = className.lastIndexOf(".");
            if (dotPos>0) {
                className = className.substring(dotPos+1);
            }
            detailObj.put("code",className);
            detailList.put(detailObj);
        }

        JSONObject innerError = new JSONObject();
        errorTag.put("innerError", innerError);

        //now do them in the opposite order for the stack trace.
        JSONArray stackList = new JSONArray();
        for (int i=traceHolder.size()-1;i>=0;i--) {
            ExceptionTracer et = traceHolder.get(i);
            if (i>0) {
                ExceptionTracer lower = traceHolder.get(i-1);
                et.removeTail(lower.trace);
            }
            et.insertIntoArray(stackList);
        }
        errorTag.put("stack", stackList);

        return responseBody;
    }
    static class ExceptionTracer {
        public Throwable t;
        public String msg;
        public List<String> trace = new ArrayList<String>();
        boolean wasTrimmed = false;

        public ExceptionTracer() {}

        public void captureTrace() {
            for (StackTraceElement ste : t.getStackTrace()) {
                String line = "    "+ste.getFileName() + ": " + ste.getMethodName() + ": " + ste.getLineNumber();
                trace.add(line);
            }
        }
        public void removeTail(List<String> lower) {
            int offUpper = trace.size()-1;
            int offLower = lower.size()-1;
            while (offUpper>0 && offLower>0
                    && trace.get(offUpper).equals(lower.get(offLower))) {
                trace.remove(offUpper);
                offUpper--;
                offLower--;
                wasTrimmed = true;
            }
        }

        public void insertIntoArray(JSONArray ja) {
            ja.put(msg);
            for (String line : trace) {
                ja.put(line);
            }
            if (wasTrimmed) {
                ja.put("    (continued below)");
            }
        }
    }
}
