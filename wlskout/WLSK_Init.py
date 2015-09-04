import base, crypto

def init():
    var_A_0 = base.read_file('wlsk_id')
    var_kAS_0 = base.size_from(32)(base.read_file('wlsk_enc_key'))
    var_mkAS_0 = base.read_file('wlsk_mac_key')
    p = proc_top(var_A_0, var_kAS_0, var_mkAS_0)
    return p.oracle_c1

class proc_top:
    def __init__(self, var_A_0, var_kAS_0, var_mkAS_0):
        self.var_A_0 = var_A_0
        self.var_kAS_0 = var_kAS_0
        self.var_mkAS_0 = var_mkAS_0
        self.token_49 = True
        
    def oracle_c1(self, input_50):
        if not self.token_49:
            raise base.BadCall()
        self.token_49 = False
        
        var_hostB2_0 = input_50
        
        pnext = proc_51(var_hostB2_0, self.var_kAS_0, self.var_mkAS_0)
        return (pnext.oracle_c3, self.var_A_0)

class proc_51:
    def __init__(self, var_hostB2_0, var_kAS_0, var_mkAS_0):
        self.var_hostB2_0 = var_hostB2_0
        self.var_kAS_0 = var_kAS_0
        self.var_mkAS_0 = var_mkAS_0
        self.token_52 = True
        
    def oracle_c3(self, input_53):
        if not self.token_52:
            raise base.BadCall()
        self.token_52 = False
        
        if base.size_pred(8)(input_53):
            var_n_134 = input_53
            
            var_r1_0 = base.random_bytes(16)
            var_e1_0 = crypto.sym_encrypt(base.concat(b'tag3', self.var_hostB2_0, var_n_134), self.var_kAS_0, var_r1_0)
            
            return (None, var_r1_0, var_e1_0, crypto.hmac_sha256_hash(var_e1_0, self.var_mkAS_0))
        else:
            raise base.BadCall()
