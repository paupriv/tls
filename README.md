# tls

This program act as server. It will listen on port (sample) 443 and act as tls v1.3 server.

It will receive the client hello from an client socket. The server parse the information and build an server hello as anwser.
Now the server sends the server hello back to the client.

I'm currently working on the encryption ECC x25519.
