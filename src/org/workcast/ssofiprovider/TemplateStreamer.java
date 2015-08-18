/*
 * OpenIDServlet.java
 */
package org.workcast.ssofiprovider;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.io.OutputStream;
import java.io.Reader;
import java.io.Writer;

/**
 * Reads a template file, searching for tokens, replacing those tokens with
 * values, and streaming the result to the output stream.
 *
 * We have called this "QuickForms" in the past. It is a lightweight mechanism
 * that allows you to create user interface screens in HTML, and then substitute
 * values into those screens as the screen is being served. Much lighter weight
 * than JSP file, there is no compiler needed.
 *
 * The file on disk is called a "template" It is a text file of any type,
 * usually HTML. There are tokens that start with two curley braces "{{" and end
 * with two curley braces "}}"
 *
 * A single brace alone will be ignored. Everything that is not between the
 * curley brace delimiter will be streamed out without change. When a token has
 * been found, the content (that is the text between the braces) will be passed
 * to the calling object in a "callback" method. The result of the callback is
 * the value to place into the template (if any).
 *
 * As a template design, you decide what token values are valuable for your
 * situation, the TemplateStreamer does not care what the tokens are. You invoke
 * the TemplateStreamer, and handle the call-backs.
 *
 * How does this compare to JSP? Well, there are no looping constructs or
 * branching constructs. It is really designed for flat files that simply need
 * some run-time values placed into them.
 *
 */
public class TemplateStreamer {

    /**
     * streamRawFile simply reads the File passed in, and streams it to output
     * byte for byte, WITHOUT any modification. This is a convenience function.
     * Exception if the file passed in does not exist. Exception if the file has
     * zero bytes length on assumption this must be a mistake.
     */
    public static void streamRawFile(OutputStream out, File resourceFile) throws Exception {

        if (!resourceFile.exists()) {
            throw new Exception("The file (" + resourceFile.toString()
                    + ") does not exist and can not be streamed as a template.");
        }

        InputStream is = new FileInputStream(resourceFile);
        byte[] buf = new byte[800];
        int amt = is.read(buf);
        int count = 0;
        while (amt >= 0) {
            out.write(buf, 0, amt);
            count += amt;
            amt = is.read(buf);
        }
        is.close();
        out.flush();

        if (count == 0) {
            throw new Exception("Hey, the resource (" + resourceFile + ") had zero bytes in it!");
        }
    }

    /**
     * Another convenience routine. Does the proper encoding for a value to be
     * placed in an HTML file, and have it display exactly as the string is in
     * Java. Always HTML encode all userentered data..
     */
    public static void writeHtml(Writer w, String t) throws Exception {
        if (t == null) {
            return; // treat it like an empty string, don't write "null"
        }
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            switch (c) {
            case '&':
                w.write("&amp;");
                continue;
            case '<':
                w.write("&lt;");
                continue;
            case '>':
                w.write("&gt;");
                continue;
            case '"':
                w.write("&quot;");
                continue;
            default:
                w.write(c);
                continue;
            }
        }
    }

    public static void streamTemplate(Writer out, File file, String charset,
            TemplateTokenRetriever ttr) throws Exception {
        try {
            InputStream is = new FileInputStream(file);
            Reader isr = new InputStreamReader(is, charset);
            streamTemplate(out, isr, ttr);
            isr.close();
            out.flush();
        }
        catch (Exception e) {
            throw new Exception("Error with template file (" + file + ").", e);
        }
    }

    /**
     * Read a text file from the Reader, and output it to the Writer while
     * searching for and substituting tokens.
     *
     * Example text might be:
     *
     * Hello {{customer}},
     *
     * Two curley braces occur before the token. Then the token, Finally two
     * closing braces after the token. Whatever is between is the token. Token
     * can have any characters EXCEPT closing curley braces.
     */
    public static void streamTemplate(Writer out, Reader template, TemplateTokenRetriever ttr)
            throws Exception {
        LineNumberReader lnr = new LineNumberReader(template);

        while (true) {

            int ch = lnr.read();
            if (ch < 0) {
                return;
            }

            if (ch != '{') {
                out.write(ch);
                continue;
            }

            ch = lnr.read();
            if (ch < 0) {
                return;
            }

            if (ch != '{') {
                out.write('{');
                out.write(ch);
                continue;
            }

            // now we definitely have a token
            int tokenLineStart = lnr.getLineNumber();

            try {
                StringBuffer tokenVal = new StringBuffer();
                ch = lnr.read();
                if (ch < 0) {
                    throw new Exception(
                            "Template source stream ended before finding a closing brace character");
                }

                while (ch != '}') {
                    tokenVal.append((char) ch);
                    ch = lnr.read();
                    if (ch < 0) {
                        throw new Exception(
                                "Template source stream ended before finding a closing brace character");
                    }
                }

                // now we have see the closing brace
                ttr.writeTokenValue(out, tokenVal.toString());

                // read one more character, to get rid of the second closing
                // brace.
                ch = lnr.read();
                if (ch != '}') {
                    throw new Exception(
                            "Found one, but did not find the second closing brace character");
                }
            }
            catch (Exception e) {
                throw new Exception("Problem with template token starting on line "
                        + tokenLineStart, e);
            }
        }
    }

}
