import base, crypto

def ONS_AGenKey_setup():
    p0 = proc_0()
    return p0.oracle_OAGK

class proc_0:
    def __init__(self):
        self.token_39 = True
        
    def oracle_OAGK(self):
        if not self.token_39:
            raise base.BadCall()
        self.token_39 = False
        
        
        var_A_0 = base.concat(base.get_hostname(), b'A')
        base.write_file('idA', var_A_0)
        
        try:
            bvar_40 = crypto.pk_keygen(4096)
            (var_pkA_0, var_skA_0) = bvar_40
            
            if True:
                base.write_file('pkA', crypto.serialize_pkey(var_pkA_0))
                base.write_file('skA', crypto.serialize_skey(var_skA_0))
                base.insert_into_table('keytbl', [var_A_0, crypto.serialize_pkey(var_pkA_0)])
                
                return (None, var_pkA_0)
            else:
                raise base.MatchFail()
        except base.MatchFail:
            raise Exception('Bad argument')
