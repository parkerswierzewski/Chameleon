Chameleon
---------
A Python Password Sprayer

## Table of Contents
 - [Disclaimer](#disclaimer)
 - [Description](#description)
   - [What is Password Spraying?](#what-is-password-spraying)
 - [Installation](#installation)
 - [Documentation](#documentation)
   - [Required Arguments](#required-arguments)
   - [Optional Arguments](#optional-arguments)
   - [Examples](#examples)
 - [Future Updates](#future-updates)

## Disclaimer
This tool was created for educational purposes. Only use this tool on systems 
you have ownership of or have written consent to test on and do not use this 
tool for illegal purposes! I am not responsible for any misuse of this tool.

## Description
Chameleon is a password sprayer that makes use of multithreading in Python. The tool
was developed for my CSEC 380 project "Is Python Faster than C: Writing a Password Sprayer 
in Python using Multithreading." The goal of this project was to write a password sprayer 
that was faster or as fast as Hydra (If you don't know what Hydra is you can find more about 
it [here](https://github.com/vanhauser-thc/thc-hydra)). The results can be found on my blog post. 

Currently Chameleon only supports the following protocols:
- SSH

What is Password Spraying?
--------------------------
Password spraying is the process of attempting to find credentials across multiple systems and is a form 
of brute force. However, a brute force attack is a targeted attack and easy to see on a network. Password 
spraying isn’t targeted against a single system and is somewhat tough to see on a network. It’s tough to 
see on the network, because it attempts to login with random usernames and passwords on systems in a random 
order. On the network, it’ll just look like a user incorrectly entered their username and/or password.

## Installation
Make sure you have GIT and PIP installed on the system!
```
git clone https://github.com/parkerswierzewski/Chameleon.git
pip -r requirements.txt
python3 chameleon.py -h
```
You're good to go :)

## Documentation
Required Arguments
------------------
| Argument | Description |
| ---      | ---         |
| `-l`	   | Specifies the login list |
| `-p`     | Specifies the password list |
| `host`   | Specifies the host, port, and protocol |

For Chameleon to function as intended you'll need to specify a login and password list as well
as specifying the host. The login and password lists should be some sort of readable text file
filled with potential usernames and passwords. Host should be in the format protocol://server:port.
If you are specifying a target list file the host field should be in the format protocol:port.

Look below optional arguments for examples.

Optional Arguments
------------------
| Argument | Description |
| ---      | ---         |
| `-h`	   | Displays the help page |
| `-t`	   | Specifies the target list |
| `-v`     | Toggles verbose mode on |

Examples
--------
```
python3 chameleon.py -h
    - Displays the help page. (Note: If -h is listed only the help page will run!) 

python3 chameleon.py -l login.txt -p passwords.txt ssh://192.168.1.0:22 -v
    - Toggles verbose mode and attempts to login with SSH credentials on the IPv4 range 192.168.1.0-192.168.1.255

python3 chameleon.py -t targets.txt -l login.txt -p passwords.txt ssh:22
    - Attempts credentials on SSH, port 22, against all IPv4 addresses within targets.txt
```

Future Updates
--------------
 - [ ] Support for IPv6 addresses and hostnames.
 - [ ] Support for more protocols (FTP, MySQL, SMTP, etc.).
 - [ ] Support for users choosing thread count.
 - [ ] Improve connection handling.
 - [ ] Improve argument parsing (user friendly).
 - [ ] Bug fixing
