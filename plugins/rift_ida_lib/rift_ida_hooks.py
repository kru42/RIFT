import idaapi
from rift_ida_lib import rift_idautils,rift_func_window

class FuncMatcherHandler(idaapi.action_handler_t):

    def __init__(self, fm, demangle, fwindow):
        idaapi.action_handler_t.__init__(self)
        self.fm = fm
        self.fwindow = fwindow
        # self.fwindow = rift_func_window.FuncWindow()
        # self.fwindow.Show("RIFT")
        print("[debug] Initialized function window!")

        self.demangle = demangle

    def activate(self, ctx):
        addr = rift_idautils.ida_determine_address()
        if addr == -1:
            print("[debug] RIFT couldn't determine address mouse is pointing at!")
            return 0
        
        print(f"Selected function at address = {hex(addr)}")
        hits = self.fm.get_top_hits_for_func(addr, 5)
        if len(hits) < 1:
            print(f"No matches for function at address = {hex(addr)}")
        else: 
            if self.demangle:
                hits = self.fm.update_demangle_names(hits)   
            for index, row in hits.iterrows():
                print(f"Addr: {hex(addr)}\tMatch: {row['name2']}\tRatio: {row['ratio']}")
            self.fwindow.update_content(addr, hits)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS