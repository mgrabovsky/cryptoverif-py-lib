open Base
open Crypto

type type_oracle_cA3 = (string * string) -> unit
 and type_oracle_cA1 = (string) -> ((type_oracle_cA3) * string * string)

let init () =
  let var_Kab_0= exc_bad_file "keyfile" (size_from 16) (input_string_from_file "keyfile") in
  (
   begin
     let token_7 = ref true in
     fun (input_6) ->
       if (!token_7) then
       begin
         token_7 := false;if b'X' = input_6 then
         begin
           let var_x_0 = (rand_string 8) () in
           let var_init_53 = (rand_string 16) () in
           (
             (
              begin
                let token_10 = ref true in
                fun (input_9, input_8) ->
                  if (!token_10) && ((sizep 16) input_9) then
                  begin
                    token_10 := false;
                    let var_init_27_55 = input_9 in 
                    let var_e_54 = input_8 in 
                    try
                      let bvar_11=(crypto.sym_dec var_e_54 var_Kab_0 var_init_27_55) in
                      let (bvar_12)=base.injbot_inv bvar_11 in
                      let (bvar_18,bvar_19,var_m_56)=(fun cvar_13 -> let lvar_14 = decompos cvar_13 in match lvar_14 with
                        | [cvar_17;cvar_16;cvar_15] -> (id cvar_17,(size_from 8) cvar_16,id cvar_15)
                        | _ -> raise Match_fail) bvar_12 in
                      if bvar_18=b'X' && bvar_19=var_x_0 then begin
                        ()
                      end
                      else
                        raise Match_fail
                    with Match_fail -> 
                      raise Match_fail
                  end
                  else raise Bad_call
              end)
             ,var_init_53, (crypto.sym_enc ( var_x_0) var_Kab_0 var_init_53)
           )
         end else begin 
           raise Match_fail
         end
       end
       else raise Bad_call
   end)