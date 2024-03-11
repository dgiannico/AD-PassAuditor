# What is AD-PassAuditor?

It extracts AD passwords using secretsdump (impacket), 
compares them with the haveibeenpwned database and outputs a csv as "uid,domain", 
i.e. all users with compromised passwords

# Prerequisites

## haveibeenpwned-downloader

Refer to https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader:

1. Install [.NET 6](https://dotnet.microsoft.com/en-us/download/dotnet/6.0)
2. Run `dotnet tool install --global haveibeenpwned-downloader`
3. Test to verify that everything is ok: `haveibeenpwned-downloader -h`

## impacket

Required to extract passwords from AD (N.B. obviously you need a domain admin account to perform this operation)

Refer to:
- https://github.com/fortra/impacket/tree/master/impacket
- https://pypi.org/project/impacket

### Linux

If you use **Kali**, you _should_ already have it (https://www.kali.org/tools/impacket/), otherwise:

1. `sudo apt install python3-impacket`
2. Test to verify that everything is ok: `impacket-secretsdump -h`

### Windows/Other

The tool will detect that you are not on Linux and will launch the secretsdump.py script. 
However, this requires the impacket library (You may have problems with antivirus, read later)

1. `pip install impacket`
2. Test to verify that everything is ok: `python secretsdump.py -h`
3. Secretsdump.py is already present in the folder. If you want to use another version, and indicate a different path, specify it with _--path-to-secretsdump_

### Antivirus/EDR Troubleshooting

Windows Defender will not like this element, as well as any well-made EDR. So:

1. Disable real time protection before download secretsdump.py and impacket
2. Add **exclusion** for these 2 path:
    - _path to secretsdump.py_ (E.g. C:\Users\you\Desktop\AD-PassAuditor\secretsdump.py)
    - _path to impacket_ (E.g. C:\Users\you\AppData\Local\Programs\Python\Python310\Lib\site-packages\impacket)
3. Reactivate real time protection

# Usage

1. Fill out domain.conf file reporting all the domains and related AD servers (targetName or address) you want to operate on. E.g.:
   - _example:192.168.1.10_
   - _mydomain:itdomdg2398_
   - (If you don't want to use the extract option, you can leave the server field blank, like "_example:_")
2. For complete use from scratch, perform:
   - `python AD-PassAuditor.py -u <yourADuser>`
   - You will be asked for your password to proceed with the extraction of the specified domains
   - Wait for the outcome. It could take a long time (even hours). Calculate that the pwnedpasswords_ntlm file currently weighs more than 30 GB, so it requires time both to download and for subsequent comparison. Extracting from domains can also take a long time depending on their size.
3. You can specify a base directory with _-bD_, example: `python AD-PassAuditor.py compare -bD ./Audit_06-03-2024/`
4. If you already have both the compromised passwords file and the directory containing all the extraction files, you can specify them and skip the extraction and download:
   - `python AD-PassAuditor.py -iD <inputDirectory> -iP <inputPassFile>`
   - Filenames must be: 'OutputHashes{domain}.ntds' for all domains
   - "domain" must match those specified in _domain.conf_
