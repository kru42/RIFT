"""Helper functions used by Rift Diff Applier and Rift Static Analyzer."""

import idaapi


def ida_get_call_dest(ea):
    # Get the address the cursor currently points at
    
    # Decode the instruction at the current address
    insn = idaapi.insn_t()
    if idaapi.decode_insn(insn, ea):
        # Check if the instruction is a call
        if idaapi.is_call_insn(insn):
            # Get the destination of the call
            call_dest = idc.get_operand_value(ea, 0)
            return call_dest
    
    # If the instruction is not a call, return -1
    return -1


def ida_determine_address():
    addr = idaapi.get_screen_ea()
    # Check if address is start of a function, if not, check if instruction at address is a call
    func = idaapi.get_func(addr)
    start_ea = func.start_ea
    if start_ea != addr:
        addr = ida_get_call_dest(addr)
        if addr == -1:
            return -1
    return addr


class ContextHooks(idaapi.UI_Hooks):

    def __init__(self, ctx_menu_path="RIFT/", shortcut="", icon=199):
        idaapi.UI_Hooks.__init__(self)
        self.shortcut = shortcut
        self.icon = icon
        self.ctx_menu_path = ctx_menu_path

    def finish_populating_widget_popup(self, form, popup):

        tft = idaapi.get_widget_type(form)
        idaapi.attach_action_to_popup(form, popup, "rift:display_matches", self.ctx_menu_path)
