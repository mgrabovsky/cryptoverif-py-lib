import base, crypto

def ONS_S_setup():
    var_skS_0 = crypto.load_skey(base.read_file('skS'))
    p0 = proc_0(var_skS_0)
    return p0.oracle_OS13

class proc_0:
    def __init__(self, var_skS_0):
        self.var_skS_0 = var_skS_0
        self.token_1 = True
        
    def oracle_OS13(self, input_3, input_2):
        if not self.token_1:
            raise base.BadCall()
        self.token_1 = False
        
        var_h1_0 = input_3
        var_h2_0 = input_2
        
        list_4 = base.get_from_table('keytbl')
        list_5 = []
        for (tvar_7, tvar_6) in list_4:
            (tvar_9, tvar_8) = (tvar_7, crypto.load_pkey(tvar_6))
            var_Khost_240 = tvar_9
            var_Rkey_0 = tvar_8
            if var_Khost_240 == var_h2_0:
                list_5.append((tvar_9, tvar_8))
            
        if not list_5:
            raise Exception('Bad argument')
        else:
            (tvar_9, tvar_8) = base.random_list(list_5)
            var_Khost_240 = tvar_9
            var_Rkey_0 = tvar_8
            
            return (None, var_Rkey_0, var_h2_0, crypto.pk_sign(base.concat_pk_str(var_Rkey_0, var_h2_0), self.var_skS_0))
            
            
        
