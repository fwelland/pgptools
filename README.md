# pgptools
Repo containing some PGP experiments. 


Goal of this work is to build simple to use OpenPGP encrypt/decrypt routines that 
work entirely off of InputStreams and OutputStreams for keys, clear text, and cipher text.  

Of course, inter-operability with OpenPGP and GPG is a given.

Using InputStreams is important to abstract away where the PGP public and private
keys come from.  Also, it will abstract away where clear text or cipher text comes 
from or is written to. 


## Key InputStream
A key InputStream will just be a single key, public or private.  It won't be a key
ring containing multiple keys. 

PGP key InputStream would be a stream over key data that comes of a gpg style 
export key operation.  For example, the following gpg command: 

``` 
gpg --export  --armour <userid>   > public-key.asc
```
would store a public key into a file.    An InputStream over this file could 
then be used.   

## Decrypt
Initial decrypt support does equivalent of: 

```
gpg --decrypt --user <userid>  EncryptedMessageToUserID.gpg 
```

## Encrypt
Initial encrypt support does equivalent of: 

```
gpg --encrypt --output EncryptedMessageForUserId.gpg --recipient <userid>  clear-message-to-userid.txt
```

## Additional Stuff & Features

Add in support for signed encryption like: 

```
gpg --encrypt --sign --output encrypted-to-recip-userid.pgp --local-user <userid> --recipient <recip-userid> clear-text.txt
```

Add in support to decrypt with signature verification.   

```
gpg --decrypt --output cleartext-out.txt -local-user <user-id> encrypted-file-to-userid.pgp
```

NOTE:   the above, using GP, will verify signature automatically, if the inbound cipher text is signed. 


### CLI (for simple testing)
Some examples of how the test cli works: 

```
#Simple decrypt
java -jar build/libs/pgptools-all.jar --decrypt  --input-file src/integrationTest/resources/EncryptedMessageToLukeSkywalker.pgp  --output-file /tmp/message.txt --key src/integrationTest/resources/LukeSkywalker.private-key.asc --passphrase skywalker 

#Simple encrypt
java -jar build/libs/pgptools-all.jar --encrypt --input-file src/integrationTest/resources/message-from-dv-to-ls.txt  --output-file /tmp/response.pgp --key src/integrationTest/resources/LukeSkywalker.public-key.asc  
```


### Link for Reference

* BouncyCastle:  https://www.bouncycastle.org/
* API/Layer over BC forOpenPGP:   https://github.com/neuhalje/bouncy-gpg


