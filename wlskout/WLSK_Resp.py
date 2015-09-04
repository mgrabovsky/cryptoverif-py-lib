import base, crypto

def init():
    var_A_0 = base.read_file('wlsk_id')
    var_kAS_0 = base.size_from(32)(base.read_file('wlsk_enc_key'))
    var_mkAS_0 = base.read_file('wlsk_mac_key')
    p = proc_top(var_A_0, var_kAS_0, var_mkAS_0)
    return p.oracle_c5

class proc_top:
    def __init__(self, var_A_0, var_kAS_0, var_mkAS_0):
        self.var_A_0 = var_A_0
        self.var_kAS_0 = var_kAS_0
        self.var_mkAS_0 = var_mkAS_0
        self.token_29 = True
        
    def oracle_c5(self, input_30):
        if not self.token_29:
            raise base.BadCall()
        self.token_29 = False
        
        var_hostA2_0 = input_30
        
        var_N_0 = base.random_bytes(8)
        pnext = proc_31(self.var_A_0, var_N_0, var_hostA2_0, self.var_kAS_0, self.var_mkAS_0)
        return (pnext.oracle_c7, var_N_0)

class proc_31:
    def __init__(self, var_A_0, var_N_0, var_hostA2_0, var_kAS_0, var_mkAS_0):
        self.var_A_0 = var_A_0
        self.var_N_0 = var_N_0
        self.var_hostA2_0 = var_hostA2_0
        self.var_kAS_0 = var_kAS_0
        self.var_mkAS_0 = var_mkAS_0
        self.token_32 = True
        
    def oracle_c7(self, input_35, input_34, input_33):
        if not self.token_32:
            raise base.BadCall()
        self.token_32 = False
        
        if base.size_pred(16)(input_35):
            var_iv_137 = input_35
            var_m_136 = input_34
            var_macm_135 = input_33
            
            pnext = proc_36(self.var_N_0, self.var_hostA2_0, self.var_kAS_0, self.var_mkAS_0)
            return (pnext.oracle_c9, self.var_hostA2_0, self.var_A_0, var_iv_137, var_m_136, var_macm_135)
            
            
        else:
            raise base.BadCall()

class proc_36:
    def __init__(self, var_N_0, var_hostA2_0, var_kAS_0, var_mkAS_0):
        self.var_N_0 = var_N_0
        self.var_hostA2_0 = var_hostA2_0
        self.var_kAS_0 = var_kAS_0
        self.var_mkAS_0 = var_mkAS_0
        self.token_37 = True
        
    def oracle_c9(self, input_40, input_39, input_38):
        if not self.token_37:
            raise base.BadCall()
        self.token_37 = False
        
        if base.size_pred(16)(input_40):
            var_iv2_0 = input_40
            var_m2_0 = input_39
            var_macm2_0 = input_38
            
            if crypto.hmac_sha256_verify(var_m2_0, self.var_mkAS_0, var_macm2_0):
                if base.concat(b'tag5', self.var_hostA2_0, self.var_N_0) == crypto.sym_decrypt(var_m2_0, self.var_kAS_0, var_iv2_0):
                    return None
                else:
                    raise Exception('Bad argument')
            else:
                raise Exception('Bad argument')
            
            
        else:
            raise base.BadCall()
