:#####################################################################################################
:#
:# Java home
:#
:#####################################################################################################
set JAVA_HOME=c:\Program Files\Java\jdk1.5.0_11\

:#####################################################################################################
:#
:# Path to jar file containing javax.servlet.* classes
:#
:# e.g.:
:# For Tomcat 4.1
:# set SERVLET_API_CP="D:\Program Files\Apache Software Foundation\Tomcat 4.1\common\lib\servlet.jar"
:#
:# For Tomcat 5.5
:# set SERVLET_API_CP="C:\Apache_Tomcat-5.5.23\common\lib\servlet-api.jar;C:\Apache_Tomcat-5.5.23\common\lib\jsp-api.jar"
:#
:#####################################################################################################
set SERVLET_API_CP="c:\Program Files\ApacheTomcat6.0\lib\servlet-api.jar;c:\Program Files\ApacheTomcat6.0\lib\jsp-api.jar"

:#####################################################################################################
:#
:# Path to source directory.
:#
:#####################################################################################################
set SOURCE_DIR=d:\sandbox\ps\openid

:#####################################################################################################
:#
:# Path to ant installation.
:#
:#####################################################################################################
set ANT_DIR=d:\sandbox\ps\nugen\gwt\apache-ant-1.8.1\bin\

:#####################################################################################################
:#
:# Path to build directory. nugen.war will be created here.
:# TARGET_DIR_DRIVE should have the drive letter of TARGET_DIR - a kludge till we have a smarter script
:#
:#####################################################################################################
set TARGET_DIR=d:\sandbuild\openid
set TARGET_DIR_DRIVE=D:
