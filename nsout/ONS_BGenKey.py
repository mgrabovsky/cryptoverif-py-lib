import base, crypto

def ONS_BGenKey_setup():
    p0 = proc_0()
    return p0.oracle_OBGK

class proc_0:
    def __init__(self):
        self.token_16 = True
        
    def oracle_OBGK(self):
        if not self.token_16:
            raise base.BadCall()
        self.token_16 = False
        
        
        var_B_0 = base.concat(base.get_hostname(), b'B')
        base.write_file('idB', var_B_0)
        
        try:
            bvar_17 = crypto.pk_keygen(4096)
            (var_pkB_0, var_skB_0) = bvar_17
            
            if True:
                base.write_file('pkB', crypto.serialize_pkey(var_pkB_0))
                base.write_file('skB', crypto.serialize_skey(var_skB_0))
                base.insert_into_table('keytbl', [var_B_0, crypto.serialize_pkey(var_pkB_0)])
                
                return (None, var_pkB_0)
            else:
                raise base.MatchFail()
        except base.MatchFail:
            raise Exception('Bad argument')
