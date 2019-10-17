from cred_tool import Dumper
import argparse
import pdb

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--username", help="Usernmae to login with")
    parser.add_argument("-p", "--password", help="Passwprd to login with")
    parser.add_argument("-d", "--domain", help="User domain")
    parser.add_argument("-H", "--target", help="Target host")

    args = parser.parse_args()
    username = args.username
    password = args.password
    domain = args.domain
    target = args.target
    task = Dumper(username=username, password=password, domain=domain, target=target)
