# pySSHA
Python SSHA generator with some more little stuffs

Introduction
------------
pySSHA is a simple SSHA password generator apparently like many others, it's quite easy to use:
````
python3 ssha.py -p slapdsecret
{SSHA}omu7YHgg6_uqOIN_epZtfJtGo0ruwdSr 

Usage: python ssha.py -p Password[-c SSHA hash to check]

optional arguments:
  -h, --help  show this help message and exit
  -p P        Password to encode
  -s S        Salt, 4 bytes in hex format, example "fooo": -s 666f6f6f
  -c C        {SSHA} hash to check
  -b          if {SSHA} hash is in base64 format
  -d D        Debug level

````

Dependencies
------------
Python3

Usage examples
--------------

You can adopt a specified salt for hashing, in hex format:
````
python3 ssha.py -p slapdsecret -s 74be2629
{SSHA}w5CJCwNQk44NjTYzcMZNKbE6Bu90viYp 
````

Verify if a password is valid comparing it with a SSHA hash:
````
python3 ssha.py -c {SSHA}w5CJCwNQk44NjTYzcMZNKbE6Bu90viYp -p slapdsecret
````

Same as previous but ssha hash is in base64 format (like ldapsearch output):
````
python3 ssha.py -c e1NTSEF9dzVDSkN3TlFrNDROalRZemNNWk5LYkU2QnU5MHZpWXA= -b -p slapdsecret
````

same as the previous but with maximum debug level
````
python3 ssha.py -c e1NTSEF9dzVDSkN3TlFrNDROalRZemNNWk5LYkU2QnU5MHZpWXA= -b -p slapdsecret -d3 -s 74be2629

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
