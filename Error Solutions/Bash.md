## ==Error One==

no matching host key type found. Their offer: ssh-rsa,ssh-dss

## Solution

Add the following to your SSH command:

`-oHostKeyAlgorithms=+ssh-rsa`

## ==Error Two==
sign_and_send_pubkey: no mutual signature supported

## Solution

Add the following to your SSH command:

`-oPubkeyAcceptedKeyTypes=+ssh-rsa`

## ==Error Three==

Unable to negotiate with {10.10.138.125 port 22}: no matching host key type found. Their offer: ssh-rsa,ssh-dss

## Solution

Add the following to your command:

`-o HostKeyAlgorithms=+ssh-rsa`

## ==Error Four==

It is required that your private key files are NOT accessible by others.
This private key will be ignored.

## Solution

You need to restrict the permissions of the private key:

`chmod 600 /path/to/private_key`



