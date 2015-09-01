open Base
open Crypto

type type_oracle_cB1 = (string * string) -> (unit * string * string)

let init () =
  let var_Kab_0= exc_bad_file "keyfile" (size_from 16) (input_string_from_file "keyfile") in
  (
   begin
     let token_4 = ref true in
     fun (input_3, input_2) ->
       if (!token_4) && ((sizep 16) input_3) then
       begin
         token_4 := false;
         let var_init_58 = input_3 in 
         let var_e_57 = input_2 in 
         try
           let bvar_5=(crypto.sym_dec var_e_57 var_Kab_0 var_init_58) in
           let (var_f_0)=base.injbot_inv bvar_5 in
           if true then begin
             let var_m_59 = (rand_string 8) () in
             let var_init_27_60 = (rand_string 16) () in
             (
               ()
               ,var_init_27_60, (crypto.sym_enc (compos [id b'X';id var_f_0;id ( var_m_59)]) var_Kab_0 var_init_27_60)
             )
           end
           else
             raise Match_fail
         with Match_fail -> 
           raise Match_fail
       end
       else raise Bad_call
   end)