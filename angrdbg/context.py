######################################################
# Author: Andrea Fioraldi <andreafioraldi@gmail.com> #
# License: BSD 2-Clause                              #
######################################################

import angr
import logging

l = logging.getLogger("angrdbg.context")

from .abstract_debugger import Debugger

import sys
if sys.version_info >= (3, 0):
    long = int
    _MAIN_OPTS=lambda debugger: { 'base_addr': debugger.image_base() , 'force_rebase': True}
else:
    _MAIN_OPTS=lambda debugger: { 'custom_base_addr': debugger.image_base() }


project = None
debugger = Debugger()


def reload_project(input_file=None, **kwargs):
    global project
    l.info("creating angr project...")
    if input_file is None:
        input_file = debugger.input_file()
    kwargs["main_opts"] = kwargs.get("main_opts", {})
    kwargs["main_opts"].update(_MAIN_OPTS(debugger))
    kwargs["load_options"] = kwargs.get("load_options", {})
    kwargs["load_options"]["auto_load_libs"] = False
    project = angr.Project(input_file, **kwargs)
    l.info("angr project created.")
    return project

def load_project(input_file=None, **kwargs):
    global project
    if project == None:
        return reload_project(input_file, **kwargs)
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
