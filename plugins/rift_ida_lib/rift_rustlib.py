import re
import rust_demangler

RE_RUSTLIB = r".{1,250}[\\|\/](.{1,50}-\d+\.\d+\.\d+(-.{1,20})?)[\\|\/]src[\\|\/].{1,100}\.rs"
RE_COMMITHASH = r".{1,250}rustc[\\|\/]([0-9a-zA-Z]{40})[\\|\/]"

# https://www.codeproject.com/Articles/175482/Compiler-Internals-How-Try-Catch-Throw-are-Interpr
ENV_STRINGS = {
        "Mingw-w64 runtime failure:": "gnu",
        "_CxxThrowException": "msvc",
        "std/src/sys/alloc/uefi.rs": "uefi",
}


def get_crates(sc):
    
    crates = set()
    for s in sc:
        m = re.match(RE_RUSTLIB, s)
        if not m:
            continue
        crates.add(m.group(1))

    return list(crates)


def get_commithash(sc):

    commithash = None
    for s in sc:

        m = re.match(RE_COMMITHASH, s)
        if not m:
            continue
        commithash = m.group(1)
        break

    return commithash


def determine_env(sc):

    compiler = None
    env_strings = list(ENV_STRINGS.keys())
    for s in sc:
        if s.strip("\n") in env_strings:
            compiler = ENV_STRINGS[s]
            break
    return compiler


#TODO: Needs improvement, quick and dirty solution to clean some of the names displayed by RIFT Diff Applier
def demangle_name(name):
    is_dtor = False
    if name.startswith("?dtor$"):
        m = re.match(r"(\?dtor\$.*)_ZN", name)
        if m:
            name = name.replace(m.group(1), "")
            name += "_dtor"
            is_dtor = True
    try:
        name = rust_demangler.demangle(name)
    except:
        print(f"Could not rename {name}, attempting manual demangling")
        name = name.replace("$LT$", "<")
        name = name.replace("$GT$", ">")
        name = name.replace("$C$", ",")
        name = name.replace("$u20$", " ")
        name = name.replace("..", "::")

    if is_dtor:
        name = f"dtor_{name}"
    return name
