# Getting Started
This folder hosts the source code for a go based echo server. This can be used as a tool for testing transport interface.

## Requirements
1. Golang
2. OpenSSL ( if secure echo server required )

## Folder Structure
The default location to store certificates and keys is the relative path to a folder "certs", update this in the configuration if you wish to move your credentials to a different folder.

The source code for the echo server is found in echo_server.go.

# Server Configuration
The echo server reads a JSON based configuration. The default location for this JSON file is './config.json', but if you wish to override this, you can specify the location of the JSON with the '-config' flag.

The JSON file contains the following options:
1. verbose
    1. Enable this option to output the contents of the message sent to the echo server.
1. logging
    1. Enable this option to output log all messages received to a file.
1. secure-connection
    1. Enable this option to switch to using TLS for the echo server. Note you will have to complete the credential creation prerequisite. Echo server will verify that the client certificate is signed with echo server credential. [This section](#credential-creation-for-secure-echo-server) demonstrates how to create the certificates for server and client with OpenSSL.
1. server-port
    1. Specify which port to open a socket on.
1. server-certificate-location
    1. Relative or absolute path to the server certificate generated in the credential creation prerequisite.
1. server-key-location
    1. Relative or absolute path to the server key generated in the credential creation prerequisite.
## Example Configuration
```json
{
    "verbose": false,
    "logging": false,
    "secure-connection": false,
    "server-port": "9000",
    "server-certificate-location": "./certs/server.pem",
    "server-key-location": "./certs/server.key"
}
```


## Credential Creation for secure echo server
### **Server**
Note that in order for full TLS verification to work, Common Name (CN) part in the following commands should be replaced with DNS name of the server.
#### **RSA**
The following openssl command can be used to generate self-signed server certificate:
```bash
openssl req -newkey rsa:2048 -nodes -x509 -sha256 -out certs/server.pem -keyout certs/server.key -days 365 -subj "/C=US/ST=WA/L=Place/O=YourCompany/OU=IT/CN=www.yours.com/emailAddress=yourEmail@your.com"
```
#### **EC**
```bash
openssl req -new -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) -keyout certs/server.key -out certs/server.pem -days 365 -subj "/C=US/ST=WA/L=Place/O=YourCompany/OU=IT/CN=www.your-company-website.com/emailAddress=yourEmail@your-company-website.com"
```
### Client
The following openssl commands can be used to generate client certificate:
#### **RSA**
```bash
openssl genrsa -out certs/client.key 2048

openssl req -new -key certs/client.key -out certs/client.csr -subj "/C=US/ST=WA/L=Place/O=YourCompany/OU=IT/CN=www.yours.com/emailAddress=yourEmail@your.com"

openssl x509 -req -in certs/client.csr -CA certs/server.pem -CAkey certs/server.key -CAcreateserial -out certs/client.pem -days 365 -sha256
```
#### **EC**
```bash
ecparam -genkey -name prime256v1 -out certs/client.key

openssl req -new -key certs/client.key -out certs/client.csr -subj "/C=US/ST=WA/L=Place/O=YourCompany/OU=IT/CN=www.your-company-website.com/emailAddress=yourEmail@your-company-website.com"

openssl x509 -req -in certs/client.csr -CA certs/server.pem -CAkey certs/server.key -CAcreateserial -out certs/client.pem -days 365 -sha256
```

# Running the Echo Server From the Command Line
`go run echo_server.go`
## With a Custom Config Location
`go run echo_server.go -config={config_file_path}`

Note: If you wish to run the unsecure and secure TCP tests at the same time, make sure you start a secure and unsecure echo server, this will require changing the configuration (You can create a second "secure" configuration, and pass it to the echo server via the -config flag.), as well as using seperate TCP ports.
