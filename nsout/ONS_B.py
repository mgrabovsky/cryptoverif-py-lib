import base, crypto

def ONS_B_setup():
    var_B_0 = base.read_file('idB')
    var_pkS_0 = crypto.load_pkey(base.read_file('pkS'))
    var_skB_0 = crypto.load_skey(base.read_file('skB'))
    p0 = proc_0(var_B_0, var_pkS_0, var_skB_0)
    return p0.oracle_OB7

class proc_0:
    def __init__(self, var_B_0, var_pkS_0, var_skB_0):
        self.var_B_0 = var_B_0
        self.var_pkS_0 = var_pkS_0
        self.var_skB_0 = var_skB_0
        self.token_20 = True
        
    def oracle_OB7(self, input_21):
        if not self.token_20:
            raise base.BadCall()
        self.token_20 = False
        
        var_m_236 = input_21
        
        try:
            bvar_22 = crypto.pk_dec(var_m_236, self.var_skB_0)
            bvar_23 = base.injbot_inv(bvar_22)
            (var_Na_237, var_hostY_0) = base.decompose(bvar_23)
            
            if True:
                pnext = proc_24(self.var_B_0, var_Na_237, var_hostY_0, self.var_pkS_0, self.var_skB_0)
                return (pnext.oracle_OB9, self.var_B_0, var_hostY_0)
            else:
                raise base.MatchFail()
        except base.MatchFail:
            raise Exception('Bad argument')

class proc_24:
    def __init__(self, var_B_0, var_Na_237, var_hostY_0, var_pkS_0, var_skB_0):
        self.var_B_0 = var_B_0
        self.var_Na_237 = var_Na_237
        self.var_hostY_0 = var_hostY_0
        self.var_pkS_0 = var_pkS_0
        self.var_skB_0 = var_skB_0
        self.token_25 = True
        
    def oracle_OB9(self, input_28, input_27, input_26):
        if not self.token_25:
            raise base.BadCall()
        self.token_25 = False
        
        var_pkY_0 = input_28
        if input_27 == self.var_hostY_0:
            var_ms_238 = input_26
            
            if crypto.pk_verify(base.concat_pk_str(var_pkY_0, self.var_hostY_0), self.var_pkS_0, var_ms_238):
                var_Nb_239 = base.random_bytes(8)
                pnext = proc_29(var_Nb_239, self.var_skB_0)
                return (pnext.oracle_OB11, crypto.pk_enc(base.concat(self.var_Na_237, var_Nb_239, self.var_B_0), var_pkY_0))
            else:
                raise Exception('Bad argument')
        else:
            raise Exception('Bad argument')
        

class proc_29:
    def __init__(self, var_Nb_239, var_skB_0):
        self.var_Nb_239 = var_Nb_239
        self.var_skB_0 = var_skB_0
        self.token_30 = True
        
    def oracle_OB11(self, input_31):
        if not self.token_30:
            raise base.BadCall()
        self.token_30 = False
        
        var_m3_0 = input_31
        
        try:
            bvar_32 = crypto.pk_dec(var_m3_0, self.var_skB_0)
            bvar_33 = base.injbot_inv(bvar_32)
            bvar_34 = bvar_33
            
            if bvar_34 == self.var_Nb_239:
                return None
            else:
                raise base.MatchFail()
        except base.MatchFail:
            raise Exception('Bad argument')
