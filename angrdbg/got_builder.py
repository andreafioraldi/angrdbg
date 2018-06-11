from context import get_debugger

def build_cle_got(proj, state):
    debugger = get_debugger()
    
    try:
        got_start, got_end = debugger.get_got()
    except:
        print "angrdbg: cannot find .got.plt section"
        return state
    
    entry_len = proj.arch.bits / 8
    
    got_start += 3*entry_len # skip first 3 entries
    
    '''
    print "## angr got - before ##"
    for a in xrange(got_start, got_end, entry_len):
        print "0x%x:  0x%x" % (a, state.solver.eval(getattr(state.mem[a], "uint%d_t" % proj.arch.bits).resolved))
    print
    '''
    
    empty_state = proj.factory.blank_state()
    state.memory.store(got_start, empty_state.memory.load(got_start, got_end - got_start))
    
    '''
    print "## angr got - final ##"
    for a in xrange(got_start, got_end, entry_len):
        print "0x%x:  0x%x" % (a, state.solver.eval(getattr(state.mem[a], "uint%d_t" % proj.arch.bits).resolved))
    print
    '''
    
    return state

def build_mixed_got(proj, state):
    debugger = get_debugger()
    
    try:
        got_start, got_end = debugger.get_got()
    except:
        print "angrdbg: cannot find .got.plt section"
        return state
    
    try:
        plt_start, plt_end = debugger.get_plt()
    except:
        print "angrdbg: cannot find .plt section"
        return state
    
    entry_len = proj.arch.bits / 8
    get_mem = debugger.get_dword if entry_len == 4 else debugger.get_qword
    
    got_start += 3*entry_len # skip first 3 entries
    
    '''
    print "## angr got - before ##"
    for a in xrange(got_start, got_end, entry_len):
        print "0x%x:  0x%x" % (a, state.solver.eval(getattr(state.mem[a], "uint%d_t" % proj.arch.bits).resolved))
    print
    '''
    
    empty_state = proj.factory.blank_state()
    
    for a in xrange(got_start, got_end, entry_len):
        state_val = empty_state.solver.eval(getattr(empty_state.mem[a], "uint%d_t" % proj.arch.bits).resolved)
        if state_val in proj._sim_procedures:
            if proj._sim_procedures[state_val].is_stub: # real simprocs or not?
                dbg_val = get_mem(a)
                name = proj._sim_procedures[state_val].display_name
                
                if dbg_val >= plt_end or dbg_val < plt_start: # already resolved by the loader in the dbg
                    setattr(state.mem[a], "uint%d_t" % proj.arch.bits, dbg_val)
                else:
                    ea = debugger.resolve_name(name)
                    if ea != None:
                        setattr(state.mem[a], "uint%d_t" % proj.arch.bits, ea)
                
    '''
    print "## angr got - final ##"
    for a in xrange(got_start, got_end, entry_len):
        print "0x%x:  0x%x" % (a, state.solver.eval(getattr(state.mem[a], "uint%d_t" % proj.arch.bits).resolved))
    print
    '''
    
    return state

    
def build_bind_now_got(proj, state):
    debugger = get_debugger()
    
    try:
        got_start, got_end = debugger.get_got()
    except:
        print "angrdbg: cannot find .got.plt section"
        return state
    
    try:
        plt_start, plt_end = debugger.get_plt()
    except:
        print "angrdbg: cannot find .plt section"
        return state
    
    entry_len = proj.arch.bits / 8
    get_mem = debugger.get_dword if entry_len == 4 else debugger.get_qword
    
    got_start += 3*entry_len # skip first 3 entries
    
    '''
    print "## angr got - before ##"
    for a in xrange(got_start, got_end, entry_len):
        print "0x%x:  0x%x" % (a, state.solver.eval(getattr(state.mem[a], "uint%d_t" % proj.arch.bits).resolved))
    print
    '''
    
    empty_state = proj.factory.blank_state()
    
    for a in xrange(got_start, got_end, entry_len):
        state_val = empty_state.solver.eval(getattr(empty_state.mem[a], "uint%d_t" % proj.arch.bits).resolved)
        if state_val in proj._sim_procedures:
            dbg_val = get_mem(a)
            name = proj._sim_procedures[state_val].display_name
            
            if dbg_val >= plt_end or dbg_val < plt_start: # already resolved by the loader in the dbg
                setattr(state.mem[a], "uint%d_t" % proj.arch.bits, dbg_val)
            else:
                ea = debugger.resolve_name(name)
                if ea != None:
                    setattr(state.mem[a], "uint%d_t" % proj.arch.bits, ea)
                    
    '''
    print "## angr got - final ##"
    for a in xrange(got_start, got_end, entry_len):
        print "0x%x:  0x%x" % (a, state.solver.eval(getattr(state.mem[a], "uint%d_t" % proj.arch.bits).resolved))
    print
    '''
    
    return state


