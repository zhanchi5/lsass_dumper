## LSASS_DUMPER

### Description
Automated process of obtaining creds.
Overlook of a process:
  1. Enumerating host for OS, architecture
  2. Logging in via smb using impacket
  *Important Note: It will not work, unless you have administrator credentials*
  3. Uploading procdump
  4. Dumping lsass.exe
  5. Downloading dump file
  6. Cleaning up (removing dump and procdump files)
  7. Parsing dump file on localhost using pypykatz
  8. Creating conveniently readable report

### Installation
First thing you need is to make sure, that your system contains all basic requirements: [Requirements](requirements.md)

Now, you can install it using following guide: [Installation](INSTALLATION.md)



### Usage:
```bash
    python3 main.py -u <Webby> -p <W0nderQu@ck> -d <DuckBurg> -H <target_ip> -vr <0|1> --auth <psexec|wmiexec>
```
  or
```bash
  python3 main.py -u <Webby> --hashes <LM:NT> -d <DuckBurg> -L </path/to/target_file> -vr <0|1> --auth <psexc|wmiexec>
```
