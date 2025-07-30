@echo off
echo Setting up API keys for phishing detection system...

:: Set correct paths
set ROOT_DIR=..
set BACKEND_DIR=%ROOT_DIR%\backend
set KEYS_FILE=%ROOT_DIR%\api_keys.env

:: Check if API keys are already set
if exist %KEYS_FILE% (
    echo API keys file already exists.
    echo Checking for existing keys...

    for /f "tokens=1,2 delims==" %%A in (%KEYS_FILE%) do (
        if /i "%%A"=="URLSCAN_API_KEY" set URLSCAN_API_KEY=%%B
        if /i "%%A"=="GOOGLE_SAFEBROWSING_API_KEY" set GOOGLE_SAFEBROWSING_API_KEY=%%B
    )

    if defined URLSCAN_API_KEY (
        echo URLScan.io API key is already set: %URLSCAN_API_KEY%
    ) else (
        echo URLScan.io API key is missing. You will be prompted to enter it.
        goto :set_urlscan_key
    )

    if defined GOOGLE_SAFEBROWSING_API_KEY (
        echo Google Safe Browsing API key is already set: %GOOGLE_SAFEBROWSING_API_KEY%
    ) else (
        echo Google Safe Browsing API key is missing. You will be prompted to enter it.
        goto :set_google_key
    )

    echo All API keys are already set. Skipping setup.
    goto :install_packages
) else (
    echo API keys file does not exist. Starting setup...
    goto :set_keys
)

:set_keys
echo.
echo Please enter your API keys for external services:
echo (These keys will be stored locally and used for real-time phishing detection)
echo.

:set_urlscan_key
echo Enter your URLScan.io API key:
set /p URLSCAN_API_KEY=

:set_google_key
echo Enter your Google Safe Browsing API key:
set /p GOOGLE_SAFEBROWSING_API_KEY=

:: Save keys to the environment file
echo URLSCAN_API_KEY=%URLSCAN_API_KEY%> %KEYS_FILE%
echo GOOGLE_SAFEBROWSING_API_KEY=%GOOGLE_SAFEBROWSING_API_KEY%>> %KEYS_FILE%

echo.
echo API keys have been saved to %KEYS_FILE%
echo.

:install_packages

:: Install required Python packages
echo Installing required Python packages...
echo.

cd %BACKEND_DIR%
pip install -r requirements.txt
pip install python-whois beautifulsoup4 requests ipaddress

echo.
echo Installation complete.
echo.

echo ===========================================================
echo SETUP COMPLETE
echo.
echo To run the application, use run_app.bat
echo.
echo For URLScan.io API key registration:
echo https://urlscan.io/user/profile/
echo.
echo For Google Safe Browsing API key:
echo https://developers.google.com/safe-browsing/v4/get-started
echo ===========================================================

pause