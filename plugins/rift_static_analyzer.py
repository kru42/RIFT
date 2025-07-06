"""RIFT Static Analyzer IDA Plugin"""

import idaapi
import ida_kernwin
import idautils
import ida_ida
import json
from rift_ida_lib import rift_rustlib

# Global idastrings
sc = None

def get_file_type():
    ftype = idaapi.get_file_type_name()
    if "PE" in ftype:
        return "PE"
    elif "ELF" in ftype:
        return "ELF"
    
    
# TODO: Needs testing on other architectures and OS
def get_target_triple():
    """Determines the corresponding target triple the binary was compiled for"""
    global sc

    target_triple = None
    ftype = get_file_type()
    env = rift_rustlib.determine_env(sc)
    if env is None:
        env = "gnu" if ftype == "ELF" else "msvc"
        print(f"[warning] For file type {ftype} could not determine env, setting default to {env}")
    return f"pc-windows-{env}" if ftype == "PE" else f"unknown-linux-{env}"


class RIFTStaticAnalyzerForm(ida_kernwin.Form):

    def __init__(self):
        form = r"""
    RIFT Static Analyzer
    Metadata Extraction:
    <#Save metadata as json in:{iFileSave}>
    Single Features:
    <##Print rustc commit hash:{bRustCommitHash}> <##Print compiled rust crates:{bExtractRustCrates}>
    """
        
        args = {
            "bRustCommitHash": ida_kernwin.Form.ButtonInput(self.get_rust_commithash),
            "bExtractRustCrates": ida_kernwin.Form.ButtonInput(self.get_rust_crates),
            "iFileSave": ida_kernwin.Form.FileInput(save=True, swidth=40, hlp="JSON file (*.json)"),
        }
        global sc
        sc = idautils.Strings()
        sc = [str(s).strip("\n") for s in sc]
        ida_kernwin.Form.__init__(self, form, args)
    
    def get_rust_commithash(self, code=1):
        commit_hash = rift_rustlib.get_commithash(sc)
        print(f"Rustc commit hash: {commit_hash}") if commit_hash else print(f"Could not determine commit hash!")
    
    def get_rust_crates(self, code=2):     
        crates = rift_rustlib.get_crates(sc)
        for crate in crates:
            print(crate)


class RIFTStaticAnalyzerPlugin(idaapi.plugin_t):

    flags = idaapi.PLUGIN_FIX
    comment = "RIFT Static Analyzer"
    help = "Extract static information from rust binaries"
    wanted_name = "RIFTStaticAnalyzer"
    wanted_hotkey = ""
    dialog = None

    def init(self):

        print("Plugin initialized")
        return idaapi.PLUGIN_KEEP
    
    def run(self, arg):
        global sc
        f = RIFTStaticAnalyzerForm()
        f.Compile()
        if f.Execute() == 1:

            # Grab the target arch of the binary
            procname = ida_ida.inf_get_procname()
            if procname != "metapc":
                print(f"Only metapc supported!")
                return 0

            output = f.iFileSave.value
            if not output:
                return 0
            
            # Extract commit hash and rust crates
            commithash = rift_rustlib.get_commithash(sc)
            if commithash is None:
                print("Failed determining commithash!")
                return 0
            crates = rift_rustlib.get_crates(sc)
            if len(crates) < 1:
                print("Failed extracting rust crates!")
                return 0

            # Determine target triple based on binary architecture
            target_triple = get_target_triple()
            if target_triple is None:
               print("Failed determining target triple, setting default to pc-windows-msvc")
            arch = "i686" if idaapi.inf_is_32bit_exactly() else "x86_64"

            json_data = {
                "commithash": commithash, 
                "target_triple": target_triple,
                "arch": arch,
                "crates": crates }
            with open(output, "w+", encoding="utf-8") as f:
                json.dump(json_data, f, ensure_ascii=False, indent=4)
            print(f"Dumped static information to {output}")

        
    
plugin = RIFTStaticAnalyzerPlugin()

def PLUGIN_ENTRY():
    global plugin
    return plugin