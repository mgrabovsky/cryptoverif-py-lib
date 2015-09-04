import base, crypto

def init():
    p = proc_top()
    return p.oracle_c11

class proc_top:
    def __init__(self):
        self.token_1 = True
        
    def oracle_c11(self, input_6, input_5, input_4, input_3, input_2):
        if not self.token_1:
            raise base.BadCall()
        self.token_1 = False
        
        if base.size_pred(16)(input_4):
            var_hostA1_0 = input_6
            var_hostB0_0 = input_5
            var_iv_141 = input_4
            var_m_140 = input_3
            var_macm_139 = input_2
            
            list_7 = base.get_from_table('keytbl')
            list_8 = []
            for (tvar_11, tvar_10, tvar_9) in list_7:
                (tvar_14, tvar_13, tvar_12) = (base.size_from(32)(tvar_11), tvar_10, tvar_9)
                var_kbs_0 = tvar_14
                var_mkbs_0 = tvar_13
                if tvar_12 == var_hostB0_0:
                    list_8.append((tvar_14, tvar_13, tvar_12))
                else:
                    pass
                
                
            if not list_8:
                raise Exception('Bad argument')
            else:
                (tvar_14, tvar_13, tvar_12) = base.random_list(list_8)
                var_kbs_0 = tvar_14
                var_mkbs_0 = tvar_13
                if tvar_12 == var_hostB0_0:
                    list_15 = base.get_from_table('keytbl')
                    list_16 = []
                    for (tvar_19, tvar_18, tvar_17) in list_15:
                        (tvar_22, tvar_21, tvar_20) = (base.size_from(32)(tvar_19), tvar_18, tvar_17)
                        var_kas_0 = tvar_22
                        var_mkas_0 = tvar_21
                        if tvar_20 == var_hostA1_0:
                            list_16.append((tvar_22, tvar_21, tvar_20))
                        else:
                            pass
                        
                        
                    if not list_16:
                        raise Exception('Bad argument')
                    else:
                        (tvar_22, tvar_21, tvar_20) = base.random_list(list_16)
                        var_kas_0 = tvar_22
                        var_mkas_0 = tvar_21
                        if tvar_20 == var_hostA1_0:
                            if crypto.hmac_sha256_verify(var_m_140, var_mkas_0, var_macm_139):
                                try:
                                    bvar_23 = crypto.sym_decrypt(var_m_140, var_kas_0, var_iv_141)
                                    bvar_24 = base.injbot_inv(bvar_23)
                                    (bvar_25, bvar_26, var_n_142) = base.decompose(bvar_24)
                                    
                                    if bvar_25 == b'tag3' and bvar_26 == var_hostB0_0:
                                        var_r3_0 = base.random_bytes(16)
                                        var_e3_0 = crypto.sym_encrypt(base.concat(b'tag5', var_hostA1_0, var_n_142), var_kbs_0, var_r3_0)
                                        
                                        return (None, var_r3_0, var_e3_0, crypto.hmac_sha256_hash(var_e3_0, var_mkbs_0))
                                    else:
                                        raise base.MatchFail()
                                except base.MatchFail:
                                    raise Exception('Bad argument')
                            else:
                                raise Exception('Bad argument')
                        else:
                            raise Exception('Bad argument')
                        
                        
                else:
                    raise Exception('Bad argument')
                
                
            
            
            
            
        else:
            raise base.BadCall()
