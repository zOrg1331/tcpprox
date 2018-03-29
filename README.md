tcpprox
------

A simple TCP proxy written in GO. Allows for proxy-ing TCP connections as well as TLS wrapped TCP connections.

Can be run simply from the command-line using arguments. Or supplying a config file. Or both.
_The command line arguments have precidence and override the config file_

Usage
----
To create a TLS proxy using the supplied config file:

`tcpprox -local-tls -remote-tls -config config.json -remote 172.16.0.12:4550`

To create a normal TCP proxy, no config file:

`tcpprox -listen 0.0.0.0:8081 -remote 172.16.0.12:8081`

To specify a custom certificate to use (PEM format) you can use the -cert option:

`tcpprox -local-tls -remote-tls -c config.json -local-cert cert.pem -local-key key.pem`

To generate valid certificate and key:

`
openssl genrsa -out server.key 2048
openssl req -new -x509 -key server.key -out server.pem -days 3650
`
To convert the certificate to DER format:

`openssl x509 -in server.pem -out server.crt -outform der`
