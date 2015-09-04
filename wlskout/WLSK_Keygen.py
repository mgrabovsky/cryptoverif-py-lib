import base, crypto

def init():
    p = proc_top()
    return p.oracle_start

class proc_top:
    def __init__(self):
        self.token_45 = True
        
    def oracle_start(self, input_46):
        if not self.token_45:
            raise base.BadCall()
        self.token_45 = False
        
        var_hostname_0 = input_46
        
        var_A_0 = var_hostname_0
        base.write_file('wlsk_id', var_A_0)
        
        var_rKas_0 = base.random_bytes(32)
        var_kAS_0 = var_rKas_0
        base.write_file('wlsk_enc_key', var_kAS_0)
        
        var_rmKas_0 = base.random_bytes(20)
        var_mkAS_0 = var_rmKas_0
        base.write_file('wlsk_mac_key', var_mkAS_0)
        
        base.insert_into_table('keytbl', [var_kAS_0, var_mkAS_0, var_A_0])
        
        return None
