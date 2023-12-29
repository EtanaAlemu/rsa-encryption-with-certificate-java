# Store passwords in variables
keystore_password="8e0d049a2b55426badd6e47005e52e2f"
key_password="4bf5bdc900fbf6e6506be4b052bf2d99"
truststore_password="b6f810c59f6a9458d0bff69050bbd1f7"

# Generate key pair
keytool -genkeypair -alias mobile_card_management -keyalg RSA -keysize 2048 -keystore card_management_keystore.jks -validity 365 -storepass "$keystore_password" -keypass "$key_password" -dname "CN=Mobile Card Management, OU=DxValley, O=Cooperative Bank of Oromia, L=Addis Ababa, ST=Addis Ababa, C=ET"

# Export certificate
keytool -export -alias mobile_card_management -keystore card_management_keystore.jks -file mobile_card_management.crt -storepass "$keystore_password"

# Import certificate into truststore (without prompting)
keytool -import -alias mobile_card_management -file mobile_card_management.crt -keystore card_management_truststore.jks -storepass "$truststore_password" -noprompt
