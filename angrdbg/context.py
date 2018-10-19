import angr

from .abstract_debugger import Debugger

project = None
debugger = Debugger()

try:
    long
    _MAIN_OPTS=lambda debugger: { 'custom_base_addr': debugger.image_base() }
except:
    long = int
    _MAIN_OPTS=lambda debugger: { 'base_addr': debugger.image_base() , 'force_rebase': True}

def load_project():
    global project
    if project == None:
        print (" >> creating angr project...")
        project = angr.Project(debugger.input_file(),
                                main_opts=_MAIN_OPTS(debugger),
                                load_options={ "auto_load_libs": False })
        print (" >> done.")
    return project

SIMPROCS_FROM_CLE = 0
ONLY_GOT_FROM_CLE = 1
USE_CLE_MEMORY = 2
GET_ALL_DISCARD_CLE = 3

memory_types = {
    "SIMPROCS_FROM_CLE": SIMPROCS_FROM_CLE,
    "ONLY_GOT_FROM_CLE" : ONLY_GOT_FROM_CLE,
    "USE_CLE_MEMORY" : USE_CLE_MEMORY,
    "GET_ALL_DISCARD_CLE" : GET_ALL_DISCARD_CLE
}

memory_type = SIMPROCS_FROM_CLE

def set_memory_type(value):
    global memory_type
    if value not in range(0,4):
        raise ValueError("invalid memory_type")
    memory_type = value

def get_memory_type():
    global memory_type
    return memory_type

def register_debugger(dbginstance):
    global debugger
    debugger = dbginstance

def get_debugger():
    global debugger
    return debugger
