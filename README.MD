# RSA Encryption with Certificate - Java

## Description

This Java repository demonstrates the implementation of RSA encryption and decryption using certificates. It provides a comprehensive example of securing data with RSA encryption, including key generation, message encryption, and decryption. Additionally, it showcases how to use certificates for public key distribution and signature verification.

## Key Features

- **RSA Encryption/Decryption:** Learn how to use the RSA algorithm for secure data communication.

- **Certificate Handling:** Understand how to generate key pairs, create certificates, and use them for encryption and verification.

- **Signature Verification:** Explore the process of signing and verifying data to ensure its integrity and authenticity.

- **Java Security APIs:** Utilize Java's security libraries and APIs for cryptographic operations.

## Prerequisites

- Java Development Kit (JDK) installed on your machine.
- [OpenSSL](https://www.openssl.org/) for generating key pairs and certificates.

## Usage

1. **Key Pair Generation:**
   - Generate RSA key pairs for encryption and decryption.

2. **Certificate Creation:**
   - Create X.509 certificates for secure key distribution.

3. **Encryption:**
   - Encrypt sensitive data using the public key from the certificate.

4. **Decryption:**
   - Decrypt the encrypted data using the private key.

5. **Signature Verification:**
   - Sign data with the private key and verify the signature using the public key.

## Configuration

The scripts `key-gen.bat` and `key-gen.sh` are provided for convenient RSA key pair and certificate generation. Modify the scripts as needed:

### Windows (key-gen.bat)

```bat
   @echo off
   
   rem Store file paths in variables
   set "private_key_file=cert1.private.key"
   set "public_certificate_file=cert1.public.crt"
   set "password=mypassword"
   set "keystore_file=keystore.p12"
   set "alias=myalias"
   
   rem Generate private key and self-signed certificate
   openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "%private_key_file%" -out "%public_certificate_file%"  -subj "/CN=Mobile Card Management/OU=DxValley/O=Cooperative Bank of Oromia/L=Addis Ababa/ST=Addis Ababa/C=ET"
   
   rem Export certificate as PKCS12 with legacy provider
   openssl pkcs12 -inkey "%private_key_file%" -in "%public_certificate_file%" -export -out "%keystore_file%" -name "%alias%" -legacy -passout pass:%password%
```

### Linux/Unix (key-gen.sh)

```bash
   #!/bin/bash
   
   # Store passwords in variables
   private_key_file="cert1.private.key"
   public_certificate_file="cert1.public.crt"
   password="mypassword"
   keystore_file="keystore.p12"
   alias="myalias"
   
   # Generate private key and self-signed certificate
   openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "$private_key_file" -out "$public_certificate_file" -subj "/CN=Mobile Card Management/OU=DxValley/O=Cooperative Bank of Oromia/L=Addis Ababa/ST=Addis Ababa/C=ET"
   
   # Export certificate as PKCS12 with legacy provider
   openssl pkcs12 -export -inkey "$private_key_file" -in "$public_certificate_file" -out "$keystore_file" -name "$alias" -passout pass:"$password"
```

### RUN 

Execute the scripts to generate RSA key pairs and certificates:

- On Windows:
```bat
key-gen.bat 
```

- On Linux/Unix:
```bash
./key-gen.sh
```
## Configuring IntelliJ IDEA for Command-Line Arguments:
- Open your project in IntelliJ IDEA.
- Locate the `main` method of your Java class (the class containing `public static void main(String[] args)`).
- Right-click on the class and select "Run <YourClassName>.main()".
- In the top menu, go to "Run" > "Edit Configurations..."
- In the "Run/Debug Configurations" dialog, find your application configuration under the "Application" section.
- In the "Configuration" tab, find the "Program arguments" field.
- Enter the command-line arguments you want to pass to your `main` method. Each argument should be separated by a space.
- Click "OK" to save the configuration.
- Now, when you run your application, IntelliJ IDEA will pass the specified command-line arguments to the `main` method.

## Arguments

The tool accepts the following command-line arguments:

1. `<keystore_path>`: Path to the keystore file containing the RSA key pair.
2. `<keystore_password>`: Password for accessing the keystore.
3. `<alias>`: Alias of the RSA key pair within the keystore.
4. `<operation>`: The operation to perform. Supported values: `encrypt`, `decrypt`, `sign`, `verify`.
5. `<message>`: The message or payload to be processed.

## Build Artifact in IntelliJ IDEA

1. Open your project in IntelliJ IDEA.
2. Go to "File" > "Project Structure."
3. In the Project Structure dialog, select "Artifacts" on the left.
4. Click the "+" icon and choose "JAR" > "From modules with dependencies."
5. Configure the JAR settings, including the main class (e.g., `com.dxvalley.RSA`).
6. Build the artifact by selecting "Build" > "Build Project" and then "Build" > "Build Artifacts."
7. In the dropdown menu, select the name of your artifact (e.g., `RSA:jar`). 
8. Choose the desired build action (e.g., "Build"). 
9. IntelliJ IDEA will build the JAR artifact, and you can find it in the `out` directory or the directory you specified.


## Build JAR in IntelliJ IDEA
1. Open IntelliJ IDEA and ensure your project is loaded. 
2. In the IntelliJ IDEA menu, go to "View" and select "Tool Windows" > "Project" to open the Project tool window. 
3. Locate your RSA.java file in the project explorer. 
4. Right-click on RSA.java and select "Open in Terminal."
5. In the terminal, run the following commands to compile your Java code and create a JAR file:
   ```bash
      # Compile the source code
      javac RSA.java
      
      # Create a JAR file
      jar cf RSA.jar RSA.class
   ```
This will create a JAR file named RSA.jar in the same directory as your source code.

## Run
To run the application, use the following command:

```bash
   # Example: Encrypt a message
   java -cp RSA.jar com.dxvalley.RSA <keystore_path> <keystore_password> <alias> encrypt "Hello, World!"
```

Replace the placeholders `<keystore_path>`, `<keystore_password>`, `<alias>`, and `<message>` with your actual values. Adjust the <operation> argument based on the operation you want to perform.

## Example Usages
- Encrypt a message:

```bash
java -cp RSA.jar com.dxvalley.RSA keystore.p12 mypassword myalias encrypt "Hello, World!"
```
- Decrypt a message:

```bash
java -cp RSA.jar com.dxvalley.RSA keystore.p12 mypassword myalias decrypt "EncryptedBase64String"
```
- Sign a payload:

```bash
java -cp RSA.jar com.dxvalley.RSA keystore.p12 mypassword myalias sign "PayloadToSign"
```
- Verify a signature:

```bash
java -cp RSA.jar com.dxvalley.RSA keystore.p12 mypassword myalias verify "Base64EncodedSignature" "OriginalPayload"
```
**Note**: Ensure that the keystore file contains a valid RSA key pair with the specified alias. If the operations involve encryption and decryption, the input message should be within quotes to handle spaces and special characters properly.

## Contributing
Contributions are welcome! Feel free to submit issues, pull requests, or suggestions to enhance the functionality and clarity of the example.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Author
Etana Alemu