open Base
open Crypto

type type_oracle_start3 = (string) -> (unit * string * string)
 and type_oracle_start2 = unit -> (unit * string)
 and type_oracle_start = (string * string) -> ((type_oracle_start2 * type_oracle_start3) * string * string)

let init () =
  let var_Kab_0= exc_bad_file "keyfile" (size_from 16) (input_string_from_file "keyfile") in
  let var_n_0= exc_bad_file "noncefile" (size_from 8) (input_string_from_file "noncefile") in
  (
   begin
     let token_3 = ref true in
     fun (input_2, input_1) ->
       if (!token_3) && ((sizep 16) input_2) && ((sizep 8) input_1) then
       begin
         token_3 := false;
         if var_Kab_0 = input_2 then
         begin
           if var_n_0 = input_1 then
           begin
             (
               (
                begin
                  let token_4 = ref true in
                  fun () ->
                    if (!token_4) then
                    begin
                      token_4 := false;
                      let var_y_0 = (rand_string 8) () in
                      (
                        ()
                        ,( var_y_0)
                      )
                    end
                    else raise Bad_call
                end
               ,
                begin
                  let token_6 = ref true in
                  fun (input_5) ->
                    if (!token_6) then
                    begin
                      token_6 := false;let var_x_0 = input_5 in 
                      let var_z_0 = (rand_string 8) () in
                      (
                        ()
                        ,var_x_0, var_z_0
                      )
                    end
                    else raise Bad_call
                end)
               ,var_n_0, var_n_0
             )
           end else begin 
             raise Match_fail
           end
         end else begin 
           raise Match_fail
         end
       end
       else raise Bad_call
   end)