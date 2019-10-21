from cred_tool import Dumper
import argparse
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--username", help="Usernmae to login with")
    parser.add_argument("-p", "--password", help="Passwprd to login with")
    parser.add_argument("-d", "--domain", help="User domain")
    parser.add_argument("-H", "--target", help="Target host")
    parser.add_argument(
        "-L", "--target_file", help="File with targets ip, line by line"
    )

    args = parser.parse_args()
    if len(sys.argv) > 1:
        pass
    else:
        sys.exit(0)
    username = args.username
    password = args.password
    domain = args.domain

    if args.target_file:
        targets_list = []
        with open(args.target_file, "r") as f:
            targets_list = f.readlines()
        for target in targets_list:
            try:
                task = Dumper(
                    username=username,
                    password=password,
                    domain=domain,
                    target=target.strip(),
                )
                task.run()
            except:
                print(f"Something went wrong with {target}")
    else:
        target = args.target
        task = Dumper(
            username=username, password=password, domain=domain, target=target
        )
        task.run()


if __name__ == "__main__":
    main()
