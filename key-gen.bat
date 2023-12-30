@echo off

rem Store file paths in variables
set "private_key_file=cert1.private.key"
set "public_certificate_file=cert1.public.crt"
set "password=mypassword"
set "keystore_file=keystore.p12"
set "alias=myalias"

rem Generate private key and self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "%private_key_file%" -out "%public_certificate_file%"  -subj "/CN=YourCommonName/OU=YourOrganizationalUnit/O=YourOrganization/L=YourCity/ST=YourState/C=YourCountry"

rem Export certificate as PKCS12 with legacy provider
openssl pkcs12 -inkey "%private_key_file%" -in "%public_certificate_file%" -export -out "%keystore_file%" -name "%alias%" -legacy -passout pass:%password%
