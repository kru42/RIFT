import pandas as pd
from rift_ida_lib import rift_idautils
# Test func: sub_1400B6390
class RIFTFuncMatcher:

    def __init__(self, path, min_ratio=0.0):
        self.path = path
        self.min_ratio = min_ratio
        self.df = self.__load_data(path)
    
    def __load_data(self, path):
        df = pd.read_json(path, lines=True)
        df["address"] = df["address"].apply(lambda x: int(x, 16))
        df = df[df["ratio"] > self.min_ratio]
        df = df[["type", "address", "name", "address2", "name2", "ratio", "description"]]
        return df

    def get_hits_for_func(self, addr):
        return self.df[self.df["address"] == addr].sort_values(by="ratio", ascending=False)
    
    def get_top_hits_for_func(self, addr, num):
        return self.get_hits_for_func(addr).head(num)
    
    def get_top_hit_name(self, addr):
        return self.get_top_hits_for_func(addr, 1).iloc["name2"]
    
    def update_demangle_names(self, df):
        """Update the pandas dataframe, replace names with demangled name."""
        df["name2"] = df["name2"].apply(rift_idautils.demangle_name)
        return df
