# SignuCA

[![Build Status](https://travis-ci.com/marcosruiz/SignuCA.svg?branch=master)](https://travis-ci.com/marcosruiz/SignuCA)

[![codecov](https://codecov.io/gh/marcosruiz/SignuCA/branch/master/graph/badge.svg)](https://codecov.io/gh/marcosruiz/SignuCA)

Certificate Authority for SignuApp

We can:
 - Add certificates using CSR
 - Revoke certificates
 - Get CRL
 - Check certificates using OCSP (in future...)
 - Get public certificate of SignuCA

### Set the structure on point

I recommend use the native command prompt of your OS to follow the following steps with Admin privileges or Git bash

You must stay in SignuTimes/ and create this directory if it does not exist

~~~
mkdir openssl 
cd openssl
mkdir ca
cd ca
mkdir private
mkdir newcerts
touch index.txt
echo 01 > serial
cd ..
~~~

### Warning

Copy openssl.cnf of `C:\Program Files\Git\mingw64\ssl` to openssl/ and edit this line `# extendedKeyUsage/` into this `extendedKeyUsage/` and edit dir to `./ca`.
Edit [tsa_config1]:

- In `dir` put TSA absolute root directory
- In `digest` put sha256 and every digest that you use

Edit [ca_config]:

- In `dir` put CA absolute root directory



### Generate a Private and Public Key for my CA

~~~
openssl genrsa -out ca/private/cakey.pem 4096
openssl req -new -x509 -days 3650 -key ca/private/cakey.pem -out ca/newcerts/cacert.pem -subj "/C=ES/ST=Zaragoza/L=Zaragoza/O=Signu/OU=Signu/CN=Signu/emailAddress=signu.app@gmail.com"
~~~

If you have this problem: unable to write 'random state'
The solution is: use terminal with admin privileges

~~~
cp ca/newcerts/cacert.pem ca
~~~

# Certificate Revocation List (CRL)

First we create some things:
~~~
cd ca
echo 01 > crlnumber
mkdir crl
cd ..
~~~

With this we create a CRL and check it:
~~~
openssl ca -config openssl.cnf -gencrl -out ca/crl/ca.crl
openssl crl -in ca/crl/ca.crl -noout -text
~~~

# SignuOCSP (Info)

## What it is an OCSP

Instead using a CRT (Certificate Revocation List) we are going to use a service OCSP (Online Certificate Status Protocol) to know if a certificate is valid or is revoked.
Because its more effective, with OCSP we can check only one certificate without download all CRT.

This service uses RFC2560 which specification is in this [link](https://www.ietf.org/rfc/rfc2560.txt).

~~~
openssl req -config ./openssl.cnf -new -nodes -out ca.csr -keyout ca.key -extensions v3_ocsp -subj "/C=ES/ST=Zaragoza/L=Zaragoza/O=Signu/OU=Signu/CN=Signu/emailAddress=signu.app@gmail.com"
openssl ca -config ./openssl.cnf -in tsacert.csr -out ca.crt -extensions v3_ocsp
openssl req -config ./openssl.cnf  -new -nodes -out dummy.csr -keyout dummy.key -subj "/C=ES/ST=Zaragoza/L=Zaragoza/O=Signu/OU=Signu/CN=Signu/emailAddress=signu.app@gmail.com"
openssl ca -config ./openssl.cnf -in dummy.csr -out dummy.crt
openssl ocsp -index index.txt -port 8888 -CA cacert.pem -rsigner ca.crt -rkey ca.key -text -out log.txt
openssl ocsp -index /etc/pki/CA/index.txt -port 8888 -rsigner ca.isrlabs.net.crt -rkey ca.isrlabs.net.key -CA /etc/pki/CA/cacert.pem -text -out log.txt
~~~


# Update .gitignore

~~~
git rm -r --cached .
git add .
git commit -m "fixed untracked files"
~~~

# Travis

First of all you need to install Ruby on your computer and RubyGems. After that you can install travis like this `gem install travis`. You may need to use super user privileges.

You have to login on travis to continue `travis login`. I use my GitHub credentials to login.

If you want to encrypt a file you have to copy this on the command line.

~~~
travis encrypt-file openssl/ca/private/cakey.pem --add
~~~

After this you will have 2 new enviroment variables that you can check on Settings, `https://travis-ci.com/marcosruiz/SignuCA/settings` in my case.

# Heroku

First go to Account Settings on Heroku website and copy API Key.

Then write on the command line this `travis encrypt $(heroku auth:token) --add deploy.api_key`. 
Write the API key from your Account Settings instead of `$(heroku auth:token)` if the command don't deploy on Heroku successfully when you push the changes.

This will deploy each time you push changes but still not decrypt the encrypted files such as cakey.pem.enc

If you want to check something of the filesystem of Heroku you have to write this command `heroku run bash --app signu-ca`

~~~





~~~
