import base, crypto

def ONS_A_setup():
    var_A_0 = base.read_file('idA')
    var_pkS_0 = crypto.load_pkey(base.read_file('pkS'))
    var_skA_0 = crypto.load_skey(base.read_file('skA'))
    p0 = proc_0(var_A_0, var_pkS_0, var_skA_0)
    return p0.oracle_OA1

class proc_0:
    def __init__(self, var_A_0, var_pkS_0, var_skA_0):
        self.var_A_0 = var_A_0
        self.var_pkS_0 = var_pkS_0
        self.var_skA_0 = var_skA_0
        self.token_43 = True
        
    def oracle_OA1(self, input_44):
        if not self.token_43:
            raise base.BadCall()
        self.token_43 = False
        
        var_hostX_0 = input_44
        
        pnext = proc_45(self.var_A_0, var_hostX_0, self.var_pkS_0, self.var_skA_0)
        return (pnext.oracle_OA3, self.var_A_0, var_hostX_0)

class proc_45:
    def __init__(self, var_A_0, var_hostX_0, var_pkS_0, var_skA_0):
        self.var_A_0 = var_A_0
        self.var_hostX_0 = var_hostX_0
        self.var_pkS_0 = var_pkS_0
        self.var_skA_0 = var_skA_0
        self.token_46 = True
        
    def oracle_OA3(self, input_49, input_48, input_47):
        if not self.token_46:
            raise base.BadCall()
        self.token_46 = False
        
        var_pkX_0 = input_49
        if input_48 == self.var_hostX_0:
            var_ms_232 = input_47
            
            if crypto.pk_verify(base.concat_pk_str(var_pkX_0, self.var_hostX_0), self.var_pkS_0, var_ms_232):
                var_Na_233 = base.random_bytes(8)
                pnext = proc_50(var_Na_233, self.var_hostX_0, var_pkX_0, self.var_skA_0)
                return (pnext.oracle_OA5, crypto.pk_enc(base.concat(var_Na_233, self.var_A_0), var_pkX_0))
            else:
                raise Exception('Bad argument')
        else:
            raise Exception('Bad argument')
        

class proc_50:
    def __init__(self, var_Na_233, var_hostX_0, var_pkX_0, var_skA_0):
        self.var_Na_233 = var_Na_233
        self.var_hostX_0 = var_hostX_0
        self.var_pkX_0 = var_pkX_0
        self.var_skA_0 = var_skA_0
        self.token_51 = True
        
    def oracle_OA5(self, input_52):
        if not self.token_51:
            raise base.BadCall()
        self.token_51 = False
        
        var_m_234 = input_52
        
        try:
            bvar_53 = crypto.pk_dec(var_m_234, self.var_skA_0)
            bvar_54 = base.injbot_inv(bvar_53)
            (bvar_55, var_Nb_235, bvar_56) = base.decompose(bvar_54)
            
            if bvar_55 == self.var_Na_233 and bvar_56 == self.var_hostX_0:
                return (None, crypto.pk_enc(var_Nb_235, self.var_pkX_0))
            else:
                raise base.MatchFail()
        except base.MatchFail:
            raise Exception('Bad argument')
