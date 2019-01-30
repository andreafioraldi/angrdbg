from .context import *
from .core import StateManager

import logging

l = logging.getLogger("angrdbg.back")

import sys
if sys.version_info >= (3, 0):
    long = int
    from .page_8 import DbgPage
else:
    bytes = str
    range = xrange
    from .page_7 import DbgPage

def full_transfer_back(state):
    if isinstance(state, StateManager):
        full_transfer_back(state.state)
        return
    
    dbg = get_debugger()
    if get_memory_type() != GET_ALL_DISCARD_CLE:
        l.warning("full_transfer_back should not be used when the memory type is not GET_ALL_DISCARD_CLE")
    
    for page in state.memory.mem._pages:
        if not isinstance(page, DbgPage):
            continue
        for i in range(len(page._storage)):
            b = page._storage[i]
            if b is None:
                continue
            v = state.solver.eval(b.obj, cast_to=int)
            dbg.put_byte(page._page_addr + i, v)
    
    for reg in load_project().arch.registers:
        v = state.solver.eval(getattr(state.regs, reg), cast_to=int)
        try: dbg.set_reg(reg, v)
        except: pass
