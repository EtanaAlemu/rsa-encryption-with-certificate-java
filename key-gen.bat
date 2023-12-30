@echo off

rem Store file paths in variables
set "private_key_file=cert1.private.key"
set "public_certificate_file=cert1.public.crt"
set "password=4bf5bdc900fbf6e6506be4b052bf2d99"
set "keystore_file=card_management_keystore.p12"
set "alias=mobile_card_management"

rem Generate private key and self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "%private_key_file%" -out "%public_certificate_file%"  -subj "/CN=Mobile Card Management/OU=DxValley/O=Cooperative Bank of Oromia/L=Addis Ababa/ST=Addis Ababa/C=ET"

rem Export certificate as PKCS12 with legacy provider
openssl pkcs12 -inkey "%private_key_file%" -in "%public_certificate_file%" -export -out "%keystore_file%" -name "%alias%" -legacy -passout pass:%password%
