CALL ./build_configuration.bat

CALL %ANT_DIR%/ant -file %SOURCE_DIR%/build/build.xml

PAUSE