import idautils
import ida_funcs
import json

OUTPUT_COUNT_FUNCS = r"C:\Tools\RustRE\Rift_Versioning\RIFT_V1\data\ralord_count_funcs.json"
OUTPUT_INSNS_LENGTH_FUNCS = r"C:\Tools\RustRE\Rift_Versioning\RIFT_V1\data\ralord_func_lengths.json"

def count_functions():
    
    result = {"total": 0, "annotated": 0, "not_annotated": 0}
    print("Count functions start")
    sub_count = 0
    non_sub_count = 0

    # Iterate over all functions
    for func_ea in idautils.Functions():
        func_name = ida_funcs.get_func_name(func_ea)
        if func_name.startswith("sub_"):
            sub_count += 1
        else:
            non_sub_count += 1
    return {"total": sub_count + non_sub_count, "annotated": sub_count, "not_annotated": non_sub_count}



def count_length_sub_functions():
    sub_functions_instructions = {}

    # Iterate over all functions
    for func_ea in idautils.Functions():
        func_name = ida_funcs.get_func_name(func_ea)
        if func_name.startswith("sub_"):
            # Count the number of instructions in the function
            func = ida_funcs.get_func(func_ea)
            instruction_count = sum(1 for _ in idautils.FuncItems(func.start_ea))
            sub_functions_instructions[func_name] = instruction_count

    return sub_functions_instructions



function_counts = count_functions()
sub_function_counts = count_length_sub_functions()

with open(OUTPUT_COUNT_FUNCS, "w+") as f:
    json.dump(function_counts, f)
    
with open(OUTPUT_INSNS_LENGTH_FUNCS, "w+") as f:
    json.dump(sub_function_counts, f)
