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


def check_dir(directory, _base_dir):  # directory exists and not empty
    return (Path(_base_dir + "/" + directory).exists() and
            any(Path(_base_dir + "/" + directory).iterdir()))


def check_file(file, _base_dir):  # file exists and not empty
    return (os.path.isfile(_base_dir + "/" + file) and
            os.path.getsize(_base_dir + "/" + file) != 0)


def create_dir(dir):
    os.makedirs(base_dir + "/" + dir, exist_ok=True)


def compare_all_hashes():
    print_separator()
    print(f"\nBegin COMPARING all hashes")
    if check_file(pwned_passwords_file, '.'):
        if check_dir(formatted_directory, base_dir):
            create_dir(compare_directory)
            with concurrent.futures.ProcessPoolExecutor() as executor:  # Multiprocessing
                executor.map(compare_domain, domains,
                             [base_dir for _ in range(len(domains))],
                             [formatted_directory for _ in range(len(domains))],
                             [compare_directory for _ in range(len(domains))],
                             [pwned_passwords_file for _ in range(len(domains))])
        else:
            raise Exception(f"\nError: no files in {formatted_directory} to continue")
    else:
        raise Exception(f"\nError: file {pwned_passwords_file} not found or empty")


def compare_domain(domain, _base_dir, _formatted_directory, _compare_directory, _pwned_passwords_file):
    print(f"\nComparing domain {domain}...")

    # Take our hashes as dictionary hash:[uid1, uid2, ...]
    our_hashes = dict()
    with open(f"{_base_dir}/{_formatted_directory}/FormattedOutputHashes-{domain}.txt", 'r', encoding="utf8") as f:
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
    with open(_pwned_passwords_file, 'r', encoding="utf8") as f:
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
    with open(f"{_base_dir}/{_compare_directory}/OutputCompare-{domain}.txt", 'w', encoding="utf8") as output:
        output.write("SamAccountName,Domain,Frequency\n")
        output.writelines(lines)

    print(f"\nComparing domain {domain} completed!")


def download_pwnedpasswords(overwrite: bool):
    print_separator()
    print("\nBegin DOWNLOAD of pwned passwords from HaveIBeenPwned "
          "(https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader)")

    command = f"haveibeenpwned-downloader.exe -n {remove_ext(pwned_passwords_file)} {'-o' if overwrite else ''}"
    os.system(command)


def extract_all_hashes():
    print_separator()
    print(f"\nBegin EXTRACTION from all domain")
    psw = getpass("\nPassword:")

    create_dir(extraction_ad_directory)
    with concurrent.futures.ProcessPoolExecutor() as executor:  # Multiprocessing
        executor.map(extract_from_dc, domains, [psw for _ in range(len(domains))],
                     [base_dir for _ in range(len(domains))],
                     [extraction_ad_directory for _ in range(len(domains))])
    print("\nExtraction complete!")


def extract_from_dc(domain, psw, _base_dir, _extraction_ad_directory):
    print(f"\nExtract from domain {domain}...")

    current_os = platform.system()
    command = f"{linux_command if current_os == 'Linux' else windows_command} -just-dc-ntlm -outputfile " \
              f"{_base_dir}/{_extraction_ad_directory}/OutputHashes-{domain} {domain}/{user}:{psw}@{domains[domain]}"
    os.system(command)


def format_all_domain_files():
    if check_dir(extraction_ad_directory, base_dir):
        print_separator()
        print("\nBegin FORMATTING all domain files...")
        create_dir(formatted_directory)
        for domain in domains:
            file_input = f"{base_dir}/{extraction_ad_directory}/OutputHashes-{domain}.ntds"
            file_output = f"{base_dir}/{formatted_directory}/FormattedOutputHashes-{domain}.txt"
            format_file(file_input, file_output)
        print("\nFormatting complete!")
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
    if check_file(domains_conf_file, '.'):
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
    if check_dir(compare_directory, base_dir):
        with open(base_dir + "/" + output_final_file, 'w', encoding='utf-8') as output_file:
            output_file.write("SamAccountName,Domain,Frequency\n")

            for domain in domains:
                file_input = f"{base_dir}/{compare_directory}/OutputCompare-{domain}.txt"
                with open(file_input, 'r', encoding='utf-8') as current_file:
                    lines = current_file.readlines()
                    output_file.write(''.join(lines[1:]))  # ignore header row
    else:
        raise Exception(f"\nError: no files in {compare_directory} to continue")


def remove_ext(s):
    return os.path.splitext(s)[0]


def print_separator():
    print("\n-------------------------------------------------------------------------")


if __name__ == '__main__':
    root_parser = define_arguments()
    args = root_parser.parse_args()

    # Parameters

    subcommand = args.subcommand
    bd = args.baseDir
    _user = args.user
    of = args.outputFilename
    ip = args.inputPassFile
    op = args.outputPassFile
    dix = args.directoryInputExtraction
    dox = args.directoryOutputExtraction
    dif = args.directoryInputFormat
    dof = args.directoryOutputFormat
    doc = args.directoryOutputCompare

    if _user:
        user = _user
        print(f"\nUser: {user}")
    else:
        if (subcommand is None and dix is None and dif is None) or subcommand == 'extract':
            root_parser.error("the following arguments are required if -dix is not specified: -u/--user")
    if bd:
        if os.path.isdir(bd):
            base_dir = str(bd).strip('/\\')
            print(f"\nBase dir: {base_dir}")
        else:
            raise argparse.ArgumentTypeError(f"The specified directory does not exist: {bd}")
    if of:
        output_final_file = of
        print(f"\nOutput final file: {output_final_file}")
    if ip:
        check_isfile(ip, '.')
        if subcommand == 'download':
            root_parser.error("argument -ip not allowed with subcommand download")
        pwned_passwords_file = str(ip).strip('/\\')
        print(f"\nInput Pass file: {'./' + pwned_passwords_file}")
    if op:
        pwned_passwords_file = remove_ext(str(op).strip('/\\'))
        print(f"\nOutput Pass file: {'./' + pwned_passwords_file}")
    if dix:
        check_isdir(dix, base_dir)
        if subcommand == 'extract':
            root_parser.error("argument -dix not allowed with subcommand extract")
        if _user:
            root_parser.error("argument -dix not allowed with argument -u/--user")
        if dif:
            root_parser.error("argument -dix not allowed with argument -dif/--directoryInputFormat")
        extraction_ad_directory = str(dix).strip('/\\')
        print(f"\nInput AD Directory: {base_dir + '/' + extraction_ad_directory}")
    if dox:
        extraction_ad_directory = str(dox).strip('/\\')
        print(f"\nOutput AD Directory: {base_dir + '/' + extraction_ad_directory}")
    if dif:
        check_isdir(dif, base_dir)
        if subcommand == 'format':
            root_parser.error("argument -dif not allowed with subcommand format")
        formatted_directory = str(dif).strip('/\\')
        print(f"\nInput Format Directory: {base_dir + '/' + formatted_directory}")
    if dof:
        formatted_directory = str(dof).strip('/\\')
        print(f"\nOutput Format Directory: {base_dir + '/' + formatted_directory}")
    if doc:
        compare_directory = str(doc).strip('/\\')
        print(f"\nOutput Compare Directory: {base_dir + '/' + compare_directory}")

    # Start script
    print_separator()
    print("\nStart...")
    st = time.time()

    get_domains_from_conf()
    if (subcommand is None and dix is None and dif is None) or subcommand == 'extract':
        extract_all_hashes()
        pass
    if (subcommand is None and dif is None) or subcommand == 'format' or (subcommand == 'compare' and dix):
        format_all_domain_files()
    if (subcommand is None and ip is None) or subcommand == 'download':
        overwrite = args.overwrite
        download_pwnedpasswords(overwrite)
        if op:
            pwned_passwords_file += '.txt'
    if subcommand is None or subcommand == 'compare':
        compare_all_hashes()
        join_all_files()
        print_separator()
        print(f"\n\nCOMPLETE! Results available at {base_dir + '/' + output_final_file}")

    # End script
    et = time.time()
    elapsed_time = et - st
    print('\nExecution time:', elapsed_time, 'seconds')
