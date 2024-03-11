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


def check_isfile(path):
    if os.path.isfile(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"The specified filename does not exist: {base_dir+'/'+path}")


def check_isdir(path):
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f"The specified directory does not exist: {base_dir + '/' + path}")


def add_baseDir_argument(parser):
    parser.add_argument("-bD", "--baseDir", metavar="<dir>", type=check_isdir,
                        help="You can specify the base directory for all subsequent operations. "
                             f"By default, it's '{base_dir}'")


def add_user_argument(parser):
    parser.add_argument("-u", "--user", metavar="<uid>", type=ascii,
                        help="Your user id for extraction (Domain Admin)")


def add_required_user_argument(parser):
    parser.add_argument("-u", "--user", metavar="<uid>", type=ascii, required=True,
                        help="Your user id for extraction (Domain Admin)")


def add_outputFilename_argument(parser):
    parser.add_argument("-oF", "--outputFilename", metavar="<filename>",
                        help=f"You can specify the output filename. "
                             "The path will be 'baseDir/outputFilename'. "
                             f"By default it's '{output_final_file}'")


def add_inputPassFile_argument(parser):
    parser.add_argument("-iP", "--inputPassFile", metavar="<filename>", type=check_isfile,
                        help="You can specify the file to use for comparison. "
                             "If not specified, the download will start. "
                             "The path is 'baseDir/inputPassFile'. "
                             f"By default, it's baseDir/{pwned_passwords_file}")


def add_outputPassFile_argument(parser):
    parser.add_argument("-oP", "--outputPassFile", metavar="<filename>",
                        help="You can specify the output filename of the download. "
                             "The path will be 'baseDir/outputPassFile'. "
                             f"By default, it's baseDir/{pwned_passwords_file}")


def add_directoryInputExtraction_argument(parser):
    parser.add_argument("-dIX", "--directoryInputExtraction", metavar="<dir>", type=check_isdir,
                        help="You can specify the directory name containing AD extraction. "
                             "The path is 'baseDir/directoryInputExtraction'. "
                             "Filenames inside must be: 'OutputHashes-{domain}.ntds' for all domains. "
                             f"By default, it's baseDir/{extraction_ad_directory}")


def add_directoryOutputExtraction_argument(parser):
    parser.add_argument("-dOX", "--directoryOutputExtraction", metavar="<dir>",
                        help="You can specify the directory name for AD extraction. "
                             "The path will be 'baseDir/directoryOutputExtraction'. "
                             "Filenames inside will be: 'OutputHashes-{domain}.ntds' for all domains. "
                             f"By default, it's baseDir/{extraction_ad_directory}")


def add_directoryInputFormat_argument(parser):
    parser.add_argument("-dIF", "--directoryInputFormat", metavar="<dir>", type=check_isdir,
                        help="You can specify the directory name containing AD extraction formatted as uid:nthash. "
                             "The path is 'baseDir/directoryInputFormat'. "
                             "Filenames inside must be: 'FormattedOutputHashes-{domain}.txt' for all domains. "
                             f"By default, it's baseDir/{formatted_directory}")


def add_directoryOutputFormat_argument(parser):
    parser.add_argument("-dOF", "--directoryOutputFormat", metavar="<dir>",
                        help="You can specify the directory name for formatting AD extraction as uid:nthash. "
                             "The path will be 'baseDir/directoryOutputFormat'. "
                             "Filenames inside will be: 'FormattedOutputHashes-{domain}.txt' for all domains. "
                             f"By default, it's baseDir/{formatted_directory}")


def add_directoryInputCompare_argument(parser):
    parser.add_argument("-dIC", "--directoryInputCompare", metavar="<dir>", type=check_isdir,
                        help="You can specify the directory name containing hashes comparison. "
                             "The path is 'baseDir/directoryInputCompare'. "
                             "Filenames inside must be: 'OutputCompare-{domain}.txt' for all domains. "
                             f"By default, it's baseDir/{compare_directory}")


def add_directoryOutputCompare_argument(parser):
    parser.add_argument("-dOC", "--directoryOutputCompare", metavar="<dir>",
                        help="You can specify the directory name for hashes comparison. "
                             "The path will be 'baseDir/directoryOutputCompare'. "
                             "Filenames inside will be: 'OutputCompare-{domain}.txt' for all domains. "
                             f"By default, it's baseDir/{compare_directory}")