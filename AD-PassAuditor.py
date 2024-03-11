import platform
import time
import concurrent.futures
from getpass import getpass
from pathlib import Path
from arguments import *

domains = {}  # Dict of domain:server to work on
# domains = {"Apps": "it03120", "IT": "it892u983"}

domains_conf_file = "domains.conf"
path_to_secretsdump = "secretsdump.py"
windows_command = f"python {path_to_secretsdump}"
linux_command = "impacket-secretsdump"


def check_dir(directory):  # directory exists and not empty
    return (Path(base_dir + "/" + directory).exists() and
            any(Path(base_dir + "/" + directory).iterdir()))


def check_file(file):  # file exists and not empty
    return (os.path.isfile(base_dir + "/" + file) and
            os.path.getsize(base_dir + "/" + file) != 0)


def compare_all_hashes():
    print(f"\nBegin comparing all hashes")
    if check_file(pwned_passwords_file):
        if check_dir(formatted_directory):
            os.makedirs(base_dir + "/" + compare_directory, exist_ok=True)
            with concurrent.futures.ProcessPoolExecutor() as executor:  # Multiprocessing
                executor.map(compare_domain, domains, [base_dir for _ in range(len(domains))])
        else:
            raise Exception(f"\nError: no files in {formatted_directory} to continue")
    else:
        raise Exception(f"\nError: file {pwned_passwords_file} not found or empty")


def compare_domain(domain, _base_dir):
    print(f"\nComparing domain {domain}...")

    # Take our hashes as dictionary hash:[uid1, uid2, ...]
    our_hashes = dict()
    with open(f"{_base_dir}/{formatted_directory}/FormattedOutputHashes-{domain}.txt", 'r', encoding="utf8") as f:
        for line in f:
            fields = line.strip().split(':')
            uid = fields[0]
            nthash = fields[1].upper()

            if nthash in our_hashes:
                our_hashes[nthash].append(uid)
            else:
                our_hashes[nthash] = [uid]

    # Compare
    matches = dict()
    with open(_base_dir + "/" + pwned_passwords_file, 'r', encoding="utf8") as f:
        for line in f:
            fields = line.strip().split(':')
            pwnedhash = fields[0]
            frequency = fields[1]
            uids = our_hashes.get(pwnedhash)
            if uids:
                for uid in uids:
                    if uid in matches:
                        matches[uid].append(frequency)
                    else:
                        matches[uid] = [frequency]

    lines = []
    for uid in matches:
        line = f"{uid},{domain},"
        for frequency in matches[uid]:
            line += frequency + "; "
        lines.append(line.strip('; ') + '\n')

    # Write to file
    with open(f"{_base_dir}/{compare_directory}/OutputCompare-{domain}.txt", 'w', encoding="utf8") as output:
        output.write("SamAccountName,Domain,Frequency\n")
        output.writelines(lines)

    print(f"\nComparing completed for domain {domain}")


def download_pwnedpasswords():
    print("\nDownloading pwned passwords from HaveIBeenPwned "
          "(https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader)")

    command = f"haveibeenpwned-downloader.exe -n {os.path.splitext(pwned_passwords_file)[0]}"
    os.system(command)


def extract_all_hashes():
    print(f"\nBegin extraction from all domain")
    psw = getpass("\nPassword:")

    os.makedirs(base_dir + "/" + extraction_ad_directory, exist_ok=True)
    with concurrent.futures.ProcessPoolExecutor() as executor:  # Multiprocessing
        executor.map(extract_from_dc, domains, [psw for _ in range(len(domains))],
                     [base_dir for _ in range(len(domains))])


def extract_from_dc(domain, psw, _base_dir):
    print(f"\nExtract from domain {domain}...")

    current_os = platform.system()
    command = f"{linux_command if current_os == 'Linux' else windows_command} -just-dc-ntlm -outputfile " \
              f"{_base_dir}/{extraction_ad_directory}/OutputHashes-{domain} {domain}/{user}:{psw}@{domains[domain]}"
    os.system(command)


def format_all_domain_files():
    if check_dir(extraction_ad_directory):
        print("\nFormatting all domain files...")
        os.makedirs(base_dir + "/" + formatted_directory, exist_ok=True)
        for domain in domains:
            file_input = f"{base_dir}/{extraction_ad_directory}/OutputHashes-{domain}.ntds"
            file_output = f"{base_dir}/{formatted_directory}/FormattedOutputHashes-{domain}.txt"
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
    if check_file(domains_conf_file):
        global domains
        print("\nDCs declared in domains.conf:\n")
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
    if check_dir(compare_directory):
        with open(base_dir + "/" + output_final_file, 'w', encoding='utf-8') as output_file:
            output_file.write("SamAccountName,Domain,Frequency\n")

            for domain in domains:
                file_input = f"{base_dir}/{compare_directory}/OutputCompare-{domain}.txt"
                with open(file_input, 'r', encoding='utf-8') as current_file:
                    lines = current_file.readlines()
                    output_file.write(''.join(lines[1:]))  # ignore header row
    else:
        raise Exception(f"\nError: no files in {compare_directory} to continue")


if __name__ == '__main__':
    root_parser = argparse.ArgumentParser(
        prog='AD-PassAuditor',
        description='Extracts AD passwords using secretsdump (impacket), '
                    'compares them with the haveibeenpwned database and outputs '
                    'a csv as "uid,domain", i.e. all users with compromised passwords. '
                    'IMPORTANT: Remember to fill in the "domains.conf" file before starting the tool',
        epilog='Remember: "With great power comes great responsibility..."', add_help=True)

    add_baseDir_argument(root_parser)  # -bD
    add_user_argument(root_parser)  # -u
    add_outputFilename_argument(root_parser)  # -oF

    # Mutual exclusion: -iP, -oP
    group = root_parser.add_mutually_exclusive_group()
    add_inputPassFile_argument(group)
    add_outputPassFile_argument(group)

    # Mutual exclusion: -dIX, -dOX
    group = root_parser.add_mutually_exclusive_group()
    add_directoryInputExtraction_argument(group)
    add_directoryOutputExtraction_argument(group)

    # Mutual exclusion: -dIF, -dOF
    group = root_parser.add_mutually_exclusive_group()
    add_directoryInputFormat_argument(group)
    add_directoryOutputFormat_argument(group)

    # Mutual exclusion: -dIC, -dOC
    group = root_parser.add_mutually_exclusive_group()
    add_directoryInputCompare_argument(group)
    add_directoryOutputCompare_argument(group)

    subparsers = root_parser.add_subparsers(title="subcommands", dest="subcommand",
                                            description="You can choose to run only individual parts")

    # Subparser for the 'extract' command
    extract_parser = subparsers.add_parser("extract", help="Extracts AD passwords using secretsdump")
    add_baseDir_argument(extract_parser)
    add_required_user_argument(extract_parser)
    add_directoryOutputExtraction_argument(extract_parser)

    # Subparser for the 'format' command
    format_parser = subparsers.add_parser("format", help="Format extraction output as a list of uid:nthash")
    add_baseDir_argument(format_parser)
    add_directoryInputExtraction_argument(format_parser)
    add_directoryOutputFormat_argument(format_parser)

    # Subparser for the 'download' command
    download_parser = subparsers.add_parser("download", help="Download pwned passwords from haveibeenpwned")
    add_baseDir_argument(download_parser)
    add_outputPassFile_argument(download_parser)

    # Subparser for the 'compare' command
    compare_parser = subparsers.add_parser("compare", help="Compare your hashes with pwned passwords and "
                                                           "outputs a csv as with the results")
    add_baseDir_argument(compare_parser)
    # Mutual exclusion: -dIX, -dIF
    group = compare_parser.add_mutually_exclusive_group()
    add_directoryInputExtraction_argument(group)
    add_directoryInputFormat_argument(group)
    add_inputPassFile_argument(compare_parser)
    add_outputFilename_argument(compare_parser)

    args = root_parser.parse_args()

    # Start script
    print("Start...")
    st = time.time()

    get_domains_from_conf()

    # Parameters
    subcommand = args.subcommand
    bd = args.baseDir
    _user = args.user
    of = args.outputFilename
    dix = args.directoryInputExtraction
    dox = args.directoryOutputExtraction
    dif = args.directoryInputFormat
    dof = args.directoryOutputFormat
    dic = args.directoryInputCompare
    doc = args.directoryOutputCompare
    ip = args.inputPassFile
    op = args.outputPassFile

    if bd:
        if os.path.isdir(bd):
            base_dir = str(bd).strip('/\\')
            print(f"\nBase dir: {base_dir}")
        else:
            raise Exception(f"\nError: the specified baseDir is not a valid directory")

    if dix:
        if subcommand == 'extract':
            root_parser.error("argument --dIX/--directoryInputExtraction: not allowed with subcommand extract")
        if _user:
            root_parser.error("argument --dIX/--directoryInputExtraction: not allowed with argument -u/--user")
        if os.path.isdir(dix):
            extraction_ad_directory = str(dix).strip('/\\')
            print(f"\nInput AD Directory: {extraction_ad_directory}")
        else:
            raise Exception(f"\nError: the specified directoryExtraction is not a valid directory")

    if (subcommand is None and dix is None) or subcommand == 'extract':
        if _user is None:
            root_parser.error("the following arguments are required: -u/--user")
        else:
            user = _user
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
