import os
import pathlib
import argparse

base_dir = "."
extraction_ad_directory = "OutputHashes"  # Directory of output files from secretsdump extractions
formatted_directory = "FormattedOutputHashes"  # Directory of output files formatted as uid:hash
compare_directory = "OutputCompare"  # Directory of output files from matching

pwned_passwords_file = "pwnedpasswords_ntlm.txt"  # File of pwned password to compare
output_final_file = "OutputMatchAllDomains.csv"  # Final output file of all domains

user = ""


def check_isfile(path, _base_dir):
    path = _base_dir + '/' + path
    if os.path.isfile(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"The specified filename does not exist: {path}")


def check_isdir(path, _base_dir):
    path = _base_dir + '/' + path
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"The specified directory does not exist: {path}")


def add_baseDir_argument(parser):
    parser.add_argument("-bd", "--baseDir", metavar="<dir>",
                        help="You can specify the base directory for all subsequent operations. "
                             f"By default, it's '{base_dir}'")


def add_user_argument(parser):
    parser.add_argument("-u", "--user", metavar="<uid>", type=ascii,
                        help="Your user id for extraction (Domain Admin)")


def add_required_user_argument(parser):
    parser.add_argument("-u", "--user", metavar="<uid>", type=ascii, required=True,
                        help="Your user id for extraction (Domain Admin)")


def add_outputFilename_argument(parser):
    parser.add_argument("-of", "--outputFilename", metavar="<filename>",
                        help=f"You can specify the output filename. "
                             "The path will be 'baseDir/outputFilename'. "
                             f"By default it's '{output_final_file}'")


def add_inputPassFile_argument(parser):
    parser.add_argument("-ip", "--inputPassFile", metavar="<filename>", nargs='+',
                        help="You can specify the file to use for comparison. "
                             "You can provide more than one (separated by space). They will be concatenated. "
                             "If not specified, the download will start. "
                             "The path is './inputPassFile'. "
                             f"By default, it's ./{pwned_passwords_file}")


def add_outputPassFile_argument(parser):
    parser.add_argument("-op", "--outputPassFile", metavar="<filename>",
                        help="You can specify the output filename of the download (without extension). "
                             "The path will be './outputPassFile.txt'. "
                             f"By default, it's ./{pwned_passwords_file}")



def add_overwrite_argument(parser):
    parser.add_argument("-o", "--overwrite", action='store_true',
                                 help="By default, if the output filename already exists, "
                                      "it will not be overwritten by haveibeenpwned-downloader. "
                                      "Use this option to overwrite it.")


def add_directoryInputExtraction_argument(parser):
    parser.add_argument("-dix", "--directoryInputExtraction", metavar="<dir>",
                        help="You can specify the directory name containing AD extraction. "
                             "The path is 'baseDir/directoryInputExtraction'. "
                             "Filenames inside must be: 'OutputHashes-{domain}.ntds' for all domains. "
                             f"By default, it's baseDir/{extraction_ad_directory}")


def add_directoryOutputExtraction_argument(parser):
    parser.add_argument("-dox", "--directoryOutputExtraction", metavar="<dir>",
                        help="You can specify the directory name for AD extraction. "
                             "The path will be 'baseDir/directoryOutputExtraction'. "
                             "Filenames inside will be: 'OutputHashes-{domain}.ntds' for all domains. "
                             f"By default, it's baseDir/{extraction_ad_directory}")


def add_directoryInputFormat_argument(parser):
    parser.add_argument("-dif", "--directoryInputFormat", metavar="<dir>",
                        help="You can specify the directory name containing AD extraction formatted as uid:nthash. "
                             "The path is 'baseDir/directoryInputFormat'. "
                             "Filenames inside must be: 'FormattedOutputHashes-{domain}.txt' for all domains. "
                             f"By default, it's baseDir/{formatted_directory}")


def add_directoryOutputFormat_argument(parser):
    parser.add_argument("-dof", "--directoryOutputFormat", metavar="<dir>",
                        help="You can specify the directory name for formatting AD extraction as uid:nthash. "
                             "The path will be 'baseDir/directoryOutputFormat'. "
                             "Filenames inside will be: 'FormattedOutputHashes-{domain}.txt' for all domains. "
                             f"By default, it's baseDir/{formatted_directory}")


def add_directoryOutputCompare_argument(parser):
    parser.add_argument("-doc", "--directoryOutputCompare", metavar="<dir>",
                        help="You can specify the directory name for hashes comparison. "
                             "The path will be 'baseDir/directoryOutputCompare'. "
                             "Filenames inside will be: 'OutputCompare-{domain}.txt' for all domains. "
                             f"By default, it's baseDir/{compare_directory}")


def define_arguments():
    root_parser = argparse.ArgumentParser(
        prog='AD-PassAuditor',
        description='Extracts AD passwords using secretsdump (impacket), '
                    'compares them with the haveibeenpwned database and outputs '
                    'a csv as "uid,domain", i.e. all users with compromised passwords. '
                    'IMPORTANT: Remember to fill in "./domains.conf" file before starting the tool',
        epilog='Remember: "With great power comes great responsibility..."', add_help=True)

    add_baseDir_argument(root_parser)  # -bd
    add_user_argument(root_parser)  # -u
    add_outputFilename_argument(root_parser)  # -of

    # Mutual exclusion: -ip, -op
    group = root_parser.add_mutually_exclusive_group()
    add_inputPassFile_argument(group)
    add_outputPassFile_argument(group)

    add_overwrite_argument(root_parser)  # -o

    # Mutual exclusion: -dix, -dox
    group = root_parser.add_mutually_exclusive_group()
    add_directoryInputExtraction_argument(group)
    add_directoryOutputExtraction_argument(group)

    # Mutual exclusion: -dif, -dof
    group = root_parser.add_mutually_exclusive_group()
    add_directoryInputFormat_argument(group)
    add_directoryOutputFormat_argument(group)

    add_directoryOutputCompare_argument(root_parser)

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
    add_outputPassFile_argument(download_parser)
    add_overwrite_argument(download_parser)

    # Subparser for the 'compare' command
    compare_parser = subparsers.add_parser("compare", help="Compare your hashes with pwned passwords and "
                                                           "outputs a csv as with the results")
    add_baseDir_argument(compare_parser)
    add_directoryInputExtraction_argument(compare_parser)
    add_directoryInputFormat_argument(compare_parser)
    add_inputPassFile_argument(compare_parser)
    add_outputFilename_argument(compare_parser)

    return root_parser
