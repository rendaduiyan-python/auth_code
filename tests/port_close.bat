ECHO OFF
set PORT=9999
set RULE_NAME="Open Port %PORT%"

netsh advfirewall firewall show rule name=%RULE_NAME% >nul
if not ERRORLEVEL 1 (
    rem Rule %RULE_NAME% already exists.
    netsh advfirewall firewall delete rule name=%RULE_NAME% dir=in protocol=TCP localport=%PORT%
    
) else (
    echo Rule %RULE_NAME% does not exist. Ingored ...
)