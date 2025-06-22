import os
import configparser

class RIFTConfig:
    def __init__(self, config_path, logger):
        self.config_path = config_path
        self.pcf = None
        self.sigmake = None
        self.diaphora = None
        self.idat = None
        self.work_folder = None
        self.cargo_proj_folder = None
        self.logger = logger
        self.flirt_available = True
        self.diff_available = True
        self.read_config()

    def read_config(self):
        config = configparser.ConfigParser()
        config.read(self.config_path)

        self.work_folder = config.get('Default', 'WorkFolder')
        if not os.path.isdir(self.work_folder):
            raise FileNotFoundError(f"{self.work_folder} does not exist. Set a valid work folder.")
        
        self.cargo_proj_folder = config.get('Default', 'CargoProjFolder')
        if not os.path.isdir(self.cargo_proj_folder):
            raise FileNotFoundError(f"{self.cargo_proj_folder} does not exist. Set a valid tmp folder")

        self.pcf = config.get('Default', 'PcfPath')
        if self.pcf == "NOT_SET" or not os.path.isfile(self.pcf):
            self.logger.warning(f"PcfPath = {self.pcf} does not exist. Flirt signature generation will be disabled.")
            self.flirt_available = False
        
        self.sigmake = config.get('Default', 'SigmakePath')
        if self.sigmake == "NOT_SET" or not os.path.isfile(self.sigmake):
            self.logger.warning(f"SigMakePath = {self.sigmake} does not exist. Flirt signature generation will be disabled.")
            self.flirt_available = False
        
        self.diaphora = config.get('Default', 'DiaphoraPath')
        if self.diaphora == 'NOT_SET' or not os.path.isfile(self.diaphora):
            self.logger.warning(f"DiaphoraPath = {self.diaphora} does not exist. Binary diffing will be disabled.")
            self.diff_available = False
        
        self.idat = config.get('Default', 'IdatPath')
        if self.idat == 'NOT_SET' or not os.path.isfile(self.idat):
            self.logger.warning(f"IdatPath = {self.idat} does not exist. Binary diffing will be disabled.")
            self.diff_available = False
        



