open Base
open Crypto

type type_oracle_cstart = unit -> unit

let init () =
  (
   begin
     let token_7 = ref true in
     fun () ->
       if (!token_7) then
       begin
         token_7 := false;
         let var_r_0 = (rand_string 16) () in
         let var_Kab_0 = ( var_r_0) in 
           output_string_to_file "keyfile" (id var_Kab_0);
         let var_n_0 = (rand_string 8) () in
         output_string_to_file "noncefile" (id var_n_0);
         ()
       end
       else raise Bad_call
   end)