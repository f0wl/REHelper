import argparse, os, sys
from terminaltables import AsciiTable
import modules.utils as util
import modules.elf as elf
import modules.pe as pe


parser = argparse.ArgumentParser(description='REHelper is an utility for initial binary analysis.')

parser.add_argument("-v", "--verbose", dest="verbose", action="store_true", default=False, help="Verbose output")
parser.add_argument('-f', '--file', metavar="filename", dest="inname", help="File to process", required=True)

args = parser.parse_args()

if not os.path.isfile(args.inname):
    sys.exit("The input file does not exist!")

with open(args.inname, "rb") as f:
    magic = f.read(4)
    if magic == b"\x7FELF":
        elf.print_basic_info(args.inname)
    else:
        pe.print_basic_info(args.inname)

interesting_strings = util.file_interesting_strings(args.inname)
tmp = []
for x in interesting_strings:
            string = ""
            for c, y in enumerate(interesting_strings[x]):
                string += y + " "
                if c % 3 == 0 and c > 0:
                    string += "\n"
            tmp.append([x + ":", string])

strings_table = [
            ["Interesting Strings", "STILL IN BETA ;)"],
        ]

for x in tmp:
    strings_table.append(x)

print(AsciiTable(table_data=strings_table, ).table)
print("")