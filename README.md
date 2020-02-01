# pySSHA-slapd
Python hashlib generator born as a script to test OpenLDAP user passwords.
It supports salted:

- md5
- sha1
- sha224
- sha256
- sha384
- sha512

Introduction
------------
pySSHA-slapd is a simple SSHA string encoder e checker that's quite easy to use:
````
python3 ssha.py -p slapdsecret
{SSHA}omu7YHgg6_uqOIN_epZtfJtGo0ruwdSr 
````
Usage
````
usage: ssha.py [-h] -p P [-s S] [-salt_size SALT_SIZE] [-c C] [-enc ENC] [-b]
               [-prefixed] [-d D]

Usage: python ssha.py -p Password[-c SSHA hash to check]

optional arguments:
  -h, --help            show this help message and exit
  -p P                  Password to encode
  -s S                  Salt, 4 bytes in hex format, example "fooo": -s
                        666f6f6f
  -salt_size SALT_SIZE  salt lenght
  -c C                  {SSHA} hash to check
  -enc ENC              Encoder to use, example: sha1 sha224 sha256 sha384
                        sha512
  -b                    if {SSHA} hash is in base64 format
  -prefixed             if suffixed or prefixed salt
  -d D                  Debug level from 1 to 5

````

Dependencies
------------
Python3 and hashlib

Usage examples
--------------

You can adopt a specified salt for hashing, in hex format:
````
python3 ssha.py -p slapdsecret -s 74be2629
{SSHA}w5CJCwNQk44NjTYzcMZNKbE6Bu90viYp 
````

Verify if a password is valid comparing it with a SSHA hash:
````
python3 ssha.py -c {SHA1}pPUGnEBCmIa+fJy6ZTS87eEg+ylVYDqcrs6oHA== -p slapdsecret 
````

Same as previous but ssha hash is in base64 format (like ldapsearch output):
````
python3 ssha.py -c e1NIQTF9dzVDSkN3TlFrNDROalRZemNNWk5LYkU2QnU5MHZpWXA= -b -p slapdsecret -salt_size 4
````

Same as the previous but with maximum debug level
````
python3 ssha.py -c e1NIQTF9dzVDSkN3TlFrNDROalRZemNNWk5LYkU2QnU5MHZpWXA= -b -p slapdsecret -d 3 -salt_size 4

[sshaSplit debug]
	ssha_password: {SSHA}w5CJCwNQk44NjTYzcMZNKbE6Bu90viYp 
	salt: 74be2629 
	payload: 0b0350938e0d8d363370c64d29b13a06ef

[checkPassword debug]
 	ssha_password:    {SSHA}w5CJCwNQk44NjTYzcMZNKbE6Bu90viYp
	created_password: {SSHA}w5CJCwNQk44NjTYzcMZNKbE6Bu90viYp
	salt: 74be2629
	password: slapdsecret

{SSHA} Check is valid: True
````

select your preferred encoder
````
python3 ssha.py -p slapdsecret -s 74be2629 -enc sha512
{SHA512}4gm2Ep0Nklb8pkss9zIs+t6/BGaGn2QYphl3UeAYuBBNW/hj8glu4jUb7JPb4LVWdCv+g0WoyYUB9VWVajQpjHS+Jik= 
````

without salt
````
python3 ssha.py -p ciao -d 3 -salt_size 0  -enc sha512
````

OpenLDAP use a 8byte lenght salt, you can also change this value with **-salt_size** option.

Resources
---------
- https://tools.ietf.org/html/rfc3174
- https://github.com/openldap/openldap/blob/master/libraries/liblutil/sha1.c
- https://github.com/openldap/openldap/blob/master/contrib/slapd-modules/passwd/sha2/README
