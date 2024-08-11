package com.purplehillsbooks.ssofi;

import java.text.SimpleDateFormat;
import java.util.Date;

import com.purplehillsbooks.json.JSONObject;
import com.purplehillsbooks.json.SimpleException;

public class SsofiException extends SimpleException {

    private SsofiException(String message, Object... values) {
        super(message, values);
    }
    private SsofiException(String message, Exception e, Object... values) {
        super(message, e, values);
    }

    public static SsofiException newBasic(String message, Object... values) {
        return new SsofiException(message, values);
    }

    public static SsofiException newWrap(String message, Exception e, Object... values) {
        return new SsofiException(message, e, values);
    }
    

    static final SimpleDateFormat dateFormatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    public static String getTraceExceptionFormat(JSONObject errOb) {
      StringBuilder sb = new StringBuilder();
      sb.append("\n~~~~~~~~~~ SSOFI EXCEPTION ~~~~~~~~~~~ ");
      String exceptionTime = dateFormatter.format(new Date());
      sb.append(exceptionTime);
      sb.append("\n");
      sb.append(errOb.toString(2));
      sb.append("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ \n");
      return sb.toString();
   }
}
