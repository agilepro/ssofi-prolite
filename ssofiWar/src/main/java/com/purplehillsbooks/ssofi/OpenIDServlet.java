/*
 * OpenIDServlet.java
 */
package com.purplehillsbooks.ssofi;

import java.io.UnsupportedEncodingException;
import java.io.Writer;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.purplehillsbooks.json.JSONException;
import com.purplehillsbooks.streams.HTMLWriter;
import com.purplehillsbooks.temps.TemplateStreamer;

/**
 * Implements an HTTPServlet for an OpenID provider
 *
 */
@SuppressWarnings("serial")
public class OpenIDServlet extends HttpServlet {

    private void setIncrediblyStrangeSecurityHeaders(HttpServletRequest req, HttpServletResponse resp) {
        try {
			req.setCharacterEncoding("UTF-8");
		} catch (UnsupportedEncodingException e) {
			//UTF-8 is always supported
		}


        //this is an API to be read by others, for these really strange rules
        //set up by the browsers, you have to set the CORS to
        //allow scripts to read this data from a browser.
        //Longer story, the browser will accept setting allow origin to '*'
        //but if you do, it will not send the cookies.  If you tell it to send
        //the cookies with "withCredentials" then it will not allows the '*'
        //setting on allow origin any more.  The only alternative is that you
        //MUST copy the origin from the request into the response.
        //This is truly strange, but required.

        String origin = req.getHeader("Origin");
        if (origin==null || origin.length()==0) {
            //if the request does not include origin, then allow any origin
            origin="*";
        }
        resp.setHeader("Access-Control-Allow-Origin",      origin);
        resp.setHeader("Access-Control-Allow-Credentials", "true");
        resp.setHeader("Access-Control-Allow-Methods",     "GET, POST, OPTIONS");
        resp.setHeader("Access-Control-Allow-Headers",     "Origin, X-Requested-With, Content-Type, Accept, Authorization");
        resp.setHeader("Access-Control-Max-Age",           "1");
        resp.setHeader("Vary",                             "*");
        resp.setHeader("Cache-Control",                    "no-cache");
    }

    /**
     * Servlet spec says that this can be called by several threads at the same
     * time. Don't use any member variables.
     */
    public void doGet(HttpServletRequest req, HttpServletResponse resp) {

        try {
            WebRequest wr = new WebRequest(req,resp);
            setIncrediblyStrangeSecurityHeaders(req,resp);
            OpenIDHandler iodh = new OpenIDHandler(wr);
            iodh.doGet();
        }
        catch (Exception e) {
            //not sure really what to do, only exception is with IO on request object
            e.printStackTrace();
        }
    }

    public void doPost(HttpServletRequest req, HttpServletResponse resp) {

        try {
            WebRequest wr = new WebRequest(req,resp);
            setIncrediblyStrangeSecurityHeaders(req,resp);
            OpenIDHandler iodh = new OpenIDHandler(wr);
            iodh.doPost();
        }
        catch (Exception e) {
            //not sure really what to do, only exception is with IO on request object
            e.printStackTrace();
        }
    }

    public void doPut(HttpServletRequest req, HttpServletResponse resp) {
        try {
            WebRequest wr = new WebRequest(req,resp);
            handleException(new Exception("Put operation not allowed on the OpenIDServlet,"), wr);
        }
        catch (Exception e) {
            //not sure really what to do, only exception is with IO on request object
            e.printStackTrace();
        }
    }

    public void doDelete(HttpServletRequest req, HttpServletResponse resp) {
        try {
            WebRequest wr = new WebRequest(req,resp);
            handleException(new Exception("Delete operation not allowed on the OpenIDServlet,"), wr);
        }
        catch (Exception e) {
            //not sure really what to do, only exception is with IO on request object
            e.printStackTrace();
        }
    }

    public void init(ServletConfig config) throws ServletException {

        // called method must not throw any exception, and must
        // remember any error encountered with the OpenIDHandler class
        OpenIDHandler.init(config);
    }

    private void handleException(Exception e, WebRequest wr) {
        try {
            Writer out = wr.w;
            wr.response.setContentType("text/html;charset=UTF-8");
            out.write("<html><body><ul><li>Exception: ");
            writeHtml(out, e.toString());
            out.write("</li></ul>\n");
            out.write("<hr/>\n");
            out.write("<a href=\"../main.jsp\" title=\"Access the main page\">Main</a>\n");
            out.write("<hr/>\n<pre>");
            JSONException.convertToJSON(e, "").write(new HTMLWriter(out),2,2);
            out.write("</pre></body></html>\n");
            out.flush();
        }
        catch (Exception eeeee) {
            // nothing we can do here...
        }
    }

    public static void writeHtml(Writer w, String t) throws Exception {
        TemplateStreamer.writeHtml(w, t);
    }

}
