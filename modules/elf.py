# ELF shit
from elftools.elf.elffile import ELFFile
from elftools.elf.descriptions import describe_e_type
from elftools.elf.sections import NullSection
# ASCII shit
from terminaltables import AsciiTable
# Common shit
from modules.utils import GREEN, RED, RESET, file_sha256sum, tinyurl, file_all_strings, file_interesting_strings, file_entropy

def print_basic_info(filename: str) -> None:
    with open(filename, "rb") as f:
        elffile = ELFFile(f) # ELF object

        # variables
        sections = ""
        debug = RED + "No" + RESET
        filesha = file_sha256sum(filename)
        vtlink = tinyurl("https://www.virustotal.com/gui/file/" + filesha)
        

        # logic
        if not vtlink:
            vtlink = "https://www.virustotal.com/gui/file/" + filesha
        for x in range(elffile.num_sections()):
            if len(elffile.get_section(x).name) > 0:
                sections += "{}{} {}({}) ".format(
                                            GREEN, elffile.get_section(x).name, RESET,
                                            hex(elffile.get_section(x).data_size))
            if x % 4 == 0 and x > 0:
                sections += "\n"
        
        if not sections:
            sections = RED + "No sections found" + RESET
        # has debug info?
        if elffile.has_dwarf_info():
            debug = GREEN + "Yes" + RESET

        info_table = [
            ["Filename:", filename],
            ["Filetype:", GREEN + "ELF " + str(elffile.get_machine_arch()) + RESET],
            ["Subsystem:", GREEN + describe_e_type(elffile.header['e_type']) + RESET],
            ["SHA256:", filesha],
            ["VT link:", vtlink],
            ["Symbols:", debug],
            ["Entropy:", str(file_entropy(filename))],
            ["Sections:\n(with size)", sections],
            ["Entrypoint:", "{}".format(hex(elffile.header["e_entry"]))]
        ]
        
        print("")
        print(AsciiTable(title="Basic Information", table_data=info_table, ).table)
        print("")
      
