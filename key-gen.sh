#!/bin/bash

# Store passwords in variables
private_key_file="cert1.private.key"
public_certificate_file="cert1.public.crt"
password="4bf5bdc900fbf6e6506be4b052bf2d99"
keystore_file="card_management_keystore.p12"
alias="mobile_card_management"

# Generate private key and self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "$private_key_file" -out "$public_certificate_file" -subj "/CN=Mobile Card Management/OU=DxValley/O=Cooperative Bank of Oromia/L=Addis Ababa/ST=Addis Ababa/C=ET"

# Export certificate as PKCS12 with legacy provider
openssl pkcs12 -export -inkey "$private_key_file" -in "$public_certificate_file" -out "$keystore_file" -name "$alias" -passout pass:"$password"
