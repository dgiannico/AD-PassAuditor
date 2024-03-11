import argparse
import os
import platform
import time
import concurrent.futures
from getpass import getpass
from pathlib import Path

domains = {}  # Dict of domain:server to work on
# domains = {"Apps": "it03120", "IT": "it892u983"}

domains_conf_file = "domains.conf"
_base_dir = "."
extraction_ad_directory = "OutputHashes2"  # Directory of output files from secretsdump extractions
formatted_output_directory = "FormattedOutputHashes"  # Directory of output files formatted as uid:hash
matches_output_directory = "OutputMatches2"  # Directory of output files from matching

pwned_passwords_file = "pwnedpasswords_ntlm.txt"  # File of pwned password to compare
output_final_file = "OutputMatchAllDomains.csv"  # Final output file of all domains

user = ""
path_to_secretsdump = "secretsdump.py"
windows_command = f"python {path_to_secretsdump}"
linux_command = "impacket-secretsdump"


def compare_all_hashes():
    print(f"\nBegin comparing all hashes")
    if (os.path.exists(_base_dir + "/" + pwned_passwords_file) and
            os.path.getsize(_base_dir + "/" + pwned_passwords_file) != 0):  # pwned_pass file exists and not empty
        if Path(_base_dir + "/" + formatted_output_directory).exists() and any(
                Path(_base_dir + "/" + formatted_output_directory).iterdir()):  # folder with hashes exists and not empty
            os.makedirs(_base_dir + "/" + matches_output_directory, exist_ok=True)
            with concurrent.futures.ProcessPoolExecutor() as executor:  # Multiprocessing
                executor.map(compare_domain, domains, [_base_dir for _ in range(len(domains))])
        else:
            raise Exception(f"\nError: no files in {formatted_output_directory} to continue")
    else:
        raise Exception(f"\nError: file {pwned_passwords_file} not found or empty")


def compare_domain(domain, base_dir):
    print(f"\nComparing domain {domain}...")

    # Take our hashes as dictionary hash:[uid1, uid2, ...]
    our_hashes = dict()
    with open(f"{base_dir}/{formatted_output_directory}/FormattedOutputHashes{domain}.txt", 'r', encoding="utf8") as f:
        for line in f:
            fields = line.strip().split(':')
            uid = fields[0]
            nthash = fields[1].upper()

            if nthash in our_hashes:
                our_hashes[nthash].append(uid)
            else:
                our_hashes[nthash] = [uid]

    # Compare
    matches = []
    with open(base_dir + "/" + pwned_passwords_file, 'r', encoding="utf8") as f:
        for line in f:
            pwnedhash = line.strip().split(':')[0]
            uids = our_hashes.get(pwnedhash)
            if uids:
                for uid in uids:
                    matches.append(f"{uid},{domain}\n")
    matches = set(matches)  # No duplicate

    # Write to file
    with open(f"{base_dir}/{matches_output_directory}/OutputMatch{domain}.txt", 'w', encoding="utf8") as output:
        output.writelines(matches)

    print(f"\nComparing completed for domain {domain}")


def download_pwnedpasswords():
    print("\nDownloading pwned passwords from HaveIBeenPwned "
          "(https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader)")

    command = f"haveibeenpwned-downloader.exe -n {os.path.splitext(pwned_passwords_file)[0]}"
    os.system(command)


def extract_all_hashes():
    print(f"\nBegin extraction from all domain")
    psw = getpass("\nPassword:")

    os.makedirs(_base_dir + "/" + extraction_ad_directory, exist_ok=True)
    with concurrent.futures.ProcessPoolExecutor() as executor:  # Multiprocessing
        executor.map(extract_from_dc, domains, [psw for _ in range(len(domains))], [_base_dir for _ in range(len(domains))])


def extract_from_dc(domain, psw, base_dir):
    print(f"\nExtract from domain {domain}...")

    current_os = platform.system()
    command = f"{linux_command if current_os == 'Linux' else windows_command} -just-dc-ntlm -outputfile " \
              f"{base_dir}/{extraction_ad_directory}/OutputHashes{domain} {domain}/{user}:{psw}@{domains[domain]}"
    os.system(command)


def format_all_domain_files():
    if Path(_base_dir + "/" + extraction_ad_directory).exists() and any(
            Path(_base_dir + "/" + extraction_ad_directory).iterdir()):  # folder with hashes exists and not empty
        print("\nFormatting all domain files...")
        os.makedirs(_base_dir + "/" + formatted_output_directory, exist_ok=True)
        for domain in domains:
            file_input = f"{_base_dir}/{extraction_ad_directory}/OutputHashes{domain}.ntds"
            file_output = f"{_base_dir}/{formatted_output_directory}/FormattedOutputHashes{domain}.txt"
            format_file(file_input, file_output)
        print("Formatting complete!")
    else:
        raise Exception(f"\nError: no files in {extraction_ad_directory} to continue")


def format_file(file_input, file_output):
    with open(file_input, 'r', encoding="utf8") as f:
        lines = f.readlines()

    with open(file_output, 'w', encoding="utf8") as f:
        for line in lines:
            if line != '\n':
                fields = line.strip().split(':')

                uid_with_domain = fields[0]
                uid = uid_with_domain.split('\\')[
                    1] if '\\' in uid_with_domain else uid_with_domain  # Remove domain if present
                nthash = fields[3]

                if not uid.endswith('$'):  # Exclude computer object
                    f.write(f"{uid}:{nthash}\n")


def get_domains_from_conf():
    if os.path.exists(domains_conf_file) and os.path.getsize(domains_conf_file) != 0:  # conf file exists and not empty
        global domains
        print("\nDCs declared in Domains.conf:\n")
        with open(domains_conf_file, 'r') as f:
            for line in f:
                if line.strip()[0] == '#':  # comment
                    pass
                else:
                    print(line)
                    fields = line.split(':')
                    domains[fields[0]] = fields[1].strip()
    else:
        raise Exception(f"\nError: file {domains_conf_file} not found or empty")


def join_all_files():
    matches_folder = Path(_base_dir + "/" + matches_output_directory)
    if matches_folder.exists() and any(matches_folder.iterdir()):
        with open(_base_dir + "/" + output_final_file, 'w', encoding='utf-8') as output_file:
            output_file.write("SamAccountName,Domain\n")

            for domain in domains:
                file_input = f"{_base_dir}/{matches_output_directory}/OutputMatch{domain}.txt"
                with open(file_input, 'r', encoding='utf-8') as current_file:
                    file_content = current_file.read()
                    output_file.write(file_content)
    else:
        raise Exception(f"\nError: no files in {matches_folder} to continue")


def add_basedir_argument(parser):
    parser.add_argument("-bD", "--baseDir",
                        help="You can specify the base directory for all subsequent operations "
                             "(unless expressly set with the other parameters). "
                             f"By default, it's {_base_dir}")


if __name__ == '__main__':
    root_parser = argparse.ArgumentParser(
        prog='AD-PassAuditor',
        description='Extracts AD passwords using secretsdump (impacket), '
                    'compares them with the haveibeenpwned database and outputs '
                    'a csv as "uid,domain", i.e. all users with compromised passwords. '
                    'IMPORTANT: Remember to fill in the "domains.conf" file before starting the tool',
        epilog='Remember: "With great power comes great responsibility..."', add_help=True)

    group = root_parser.add_mutually_exclusive_group()
    group.add_argument("-u", "--user", help="Your user id (Domain Admin)")
    group.add_argument("-iD", "--inputDirectory",
                        help="You can specify the input directory name containing AD extraction. "
                             "Filenames must be: 'OutputHashes{domain}.ntds' for all domains. "
                             f"If not set, it begins extraction in {extraction_ad_directory}")

    add_basedir_argument(root_parser)
    root_parser.add_argument("-iP", "--inputPassFile",
                             help="You can specify the file to use for comparison. "
                             f"If not set, it downloads it as {pwned_passwords_file}")
    root_parser.add_argument("-o", "--output",
                             help=f"You can specify the output filepath. "
                             f"By default it's {output_final_file}")

    subparsers = root_parser.add_subparsers(title="subcommands", dest="subcommand",
                                            description="You can choose to run only individual parts")

    # Subparser for the 'extract' command
    extract_parser = subparsers.add_parser("extract", help="Extracts AD passwords using secretsdump")
    add_basedir_argument(extract_parser)
    extract_parser.add_argument("-u", "--user", required=True, help="Your user id (Domain Admin)")
    extract_parser.add_argument("-o", "--output",
                                help="You can specify the output directory path. "
                                     f"By default it's ./{extraction_ad_directory}")

    # Subparser for the 'format' command
    format_parser = subparsers.add_parser("format", help="Format extraction output as a list of uid:nthash")
    add_basedir_argument(format_parser)
    format_parser.add_argument("-i", "--input",
                               help="You can specify the input directory path. "
                                    f"By default it's ./{extraction_ad_directory}")

    # Subparser for the 'download' command
    download_parser = subparsers.add_parser("download", help="Download pwned passwords from haveibeenpwned")
    download_parser.add_argument("-o", "--output",
                                 help=f"You can specify the output filepath. "
                                      f"By default it's {pwned_passwords_file}")

    # Subparser for the 'compare' command
    compare_parser = subparsers.add_parser("compare", help="Compare your hashes with pwned passwords and "
                                                           "outputs a csv as with the results")
    add_basedir_argument(compare_parser)
    compare_parser.add_argument("-i", "--input",
                                help="You can specify the input directory path. "
                                     f"By default it's ./{formatted_output_directory}")
    compare_parser.add_argument("-f", "--file",
                                help="You can specify the file to use for comparison. "
                                     f"By default it's {pwned_passwords_file}")
    compare_parser.add_argument("-o", "--output",
                                help="You can specify the output directory path. "
                                     f"By default it's ./{matches_output_directory}")

    args = root_parser.parse_args()

    print("Start...")
    st = time.time()
    # Start script

    get_domains_from_conf()

    subcommand = args.subcommand

    if args.baseDir:
        if os.path.isdir(args.baseDir):
            _base_dir = str(args.baseDir).strip('/\\')
            print(f"\nBase dir: {_base_dir}")
        else:
            raise Exception(f"\nError: the specified baseDir is not a valid directory")

    if (subcommand is None and args.inputDirectory is None) or subcommand == 'extract':
        if args.user is None:
            root_parser.error("the following arguments are required: -u/--user")
        else:
            user = args.user
            extract_all_hashes()
    if subcommand is None or subcommand == 'format':
        format_all_domain_files()
    if subcommand is None or subcommand == 'download':
        download_pwnedpasswords()
    if subcommand is None or subcommand == 'compare':
        compare_all_hashes()
        join_all_files()

    # End script
    et = time.time()
    elapsed_time = et - st
    print('\nExecution time:', elapsed_time, 'seconds')


