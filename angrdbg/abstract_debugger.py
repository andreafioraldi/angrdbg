
SEG_PROT_R = 4
SEG_PROT_W = 2
SEG_PROT_X = 1


class Segment(object):
    def __init__(self, name, start, end, perms):
        self.name = name
        self.start = start
        self.end = end
        self.perms = perms


class Debugger(object):
    name = "<abstract>"

    def __init__(self):
        pass

    # -------------------------------------
    def before_stateshot(self):
        pass

    def after_stateshot(self, state):
        pass

    # -------------------------------------
    def is_active(self):
        raise NotImplementedError()

    # -------------------------------------
    def input_file(self):  # the file will be closed after a read
        raise NotImplementedError()

    def image_base(self):
        raise NotImplementedError()

    # -------------------------------------
    def get_byte(self, addr):
        raise NotImplementedError()

    def get_word(self, addr):
        raise NotImplementedError()

    def get_dword(self, addr):
        raise NotImplementedError()

    def get_qword(self, addr):
        raise NotImplementedError()

    def get_bytes(self, addr, size):
        raise NotImplementedError()

    def put_byte(self, addr, value):
        raise NotImplementedError()

    def put_word(self, addr, value):
        raise NotImplementedError()

    def put_dword(self, addr, value):
        raise NotImplementedError()

    def put_qword(self, addr, value):
        raise NotImplementedError()

    def put_bytes(self, addr, value):
        raise NotImplementedError()

    # -------------------------------------
    def get_reg(self, name):
        raise NotImplementedError()

    def set_reg(self, name, value):
        raise NotImplementedError()

    # -------------------------------------
    def step_into(self):
        raise NotImplementedError()

    def run(self):
        raise NotImplementedError()

    def wait_ready(self):
        raise NotImplementedError()

    def refresh_memory(self):
        raise NotImplementedError()

    # -------------------------------------
    def seg_by_name(self, name):
        raise NotImplementedError()

    def seg_by_addr(self, name):
        raise NotImplementedError()

    def get_got(self):  # return tuple(start_addr, end_addr)
        raise NotImplementedError()

    def get_plt(self):  # return tuple(start_addr, end_addr)
        raise NotImplementedError()

    # -------------------------------------
    def resolve_name(self, name):  # return None on fail
        raise NotImplementedError()

