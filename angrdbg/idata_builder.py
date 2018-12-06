from .context import get_debugger

import logging

l = logging.getLogger("angrdbg.idata_builder")

#py2 and 3 support
try:
    xrange
except NameError:
    xrange = range


def build_cle_idata(proj, state):
    debugger = get_debugger()

    try:
        idata_start, idata_end = debugger.get_idata()
    except BaseException:
        l.warning("cannot find .idata section, build_cle_idata failed")
        return state

    entry_len = proj.arch.bits // 8
    
    empty_state = proj.factory.blank_state()
    state.memory.store(
        idata_start,
        empty_state.memory.load(
            idata_start,
            idata_end -
            idata_start))

    return state


def build_mixed_idata(proj, state):
    debugger = get_debugger()

    try:
        idata_start, idata_end = debugger.get_idata()
    except BaseException:
        l.warning("cannot find .idata section, build_mixed_idata failed")
        return state

    entry_len = proj.arch.bits // 8
    get_mem = debugger.get_dword if entry_len == 4 else debugger.get_qword

    empty_state = proj.factory.blank_state()

    for a in xrange(idata_start, idata_end, entry_len):
        state_val = empty_state.solver.eval(
            getattr(
                empty_state.mem[a],
                "uint%d_t" %
                proj.arch.bits).resolved)
        if state_val in proj._sim_procedures:
            if proj._sim_procedures[state_val].is_stub:  # real simprocs or not?
                dbg_val = get_mem(a)
                setattr(state.mem[a], "uint%d_t" % proj.arch.bits, dbg_val)
            else:
                setattr(state.mem[a], "uint%d_t" % proj.arch.bits, state_val)
                
    return state


