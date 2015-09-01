import base, crypto

def ONS_Keygen_setup():
    p0 = proc_0()
    return p0.oracle_OStart

class proc_0:
    def __init__(self):
        self.token_12 = True
        
    def oracle_OStart(self):
        if not self.token_12:
            raise base.BadCall()
        self.token_12 = False
        
        
        try:
            bvar_13 = crypto.pk_keygen(4096)
            (var_pkS_0, var_skS_0) = bvar_13
            
            if True:
                base.write_file('pkS', crypto.serialize_pkey(var_pkS_0))
                base.write_file('skS', crypto.serialize_skey(var_skS_0))
                return (None, var_pkS_0)
            else:
                raise base.MatchFail()
        except base.MatchFail:
            raise Exception('Bad argument')
