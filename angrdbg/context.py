import angr

from abstract_debugger import Debugger

project = None
debugger = Debugger()

def load_project():
    global project
    if project == None:
        print " >> creating angr project..."
        project = angr.Project(debugger.input_file_path(),
                                main_opts={ 'custom_base_addr': debugger.image_base() },
                                load_options={ "auto_load_libs": False })
        print " >> done."
    return project

SIMPROCS_FROM_CLE = 0
ONLY_GOT_FROM_CLE = 1
TEXT_GOT_FROM_CLE = 2
GET_ALL_DISCARD_CLE = 3

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
    if not isinstance(dbginstance, Debugger):
        raise TypeError("dbginstance must be an instance of abstract_debugger.Debugger")
    debugger = dbginstance

def get_debugger():
    global debugger
    return debugger
