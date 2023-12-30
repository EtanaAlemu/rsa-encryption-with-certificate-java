#!/bin/bash

# Store passwords in variables
 private_key_file="cert1.private.key"
 public_certificate_file="cert1.public.crt"
 password="mypassword"
 keystore_file="keystore.p12"
 alias="myalias"

# Generate private key and self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "$private_key_file" -out "$public_certificate_file" -subj "/CN=YourCommonName/OU=YourOrganizationalUnit/O=YourOrganization/L=YourCity/ST=YourState/C=YourCountry"

# Export certificate as PKCS12 with legacy provider
openssl pkcs12 -export -inkey "$private_key_file" -in "$public_certificate_file" -out "$keystore_file" -name "$alias" -passout pass:"$password"
