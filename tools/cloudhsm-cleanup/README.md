## CloudHSM cleanup scripts

### Background

* `contentsignaturepki` signers generate new key pairs to sign End
Entity/Leaf certs at a frequency configurable in the signer

* CloudHSM has [a limit of 3.3k keys per cluster](
https://docs.aws.amazon.com/cloudhsm/latest/userguide/limits.html)

* new key have labels in the format `<signer id>-<UTC timestamp from
when the key was generated>` e.g. `normandy-20200806150717` in
CloudHSM and a row in the autograph `endentities` table with the key
label and private key handle

These scripts help clean up old keys before hitting the limit.


### Cleaning up old key pairs

#### Find key handles for inactive key pairs

1. Source the helper functions `source hsm_cleanup_functions.sh`

1. Run `set_db_env_vars $sops_encrypted_config_file` to decrypt and
   export env vars to access the autograph database (this might take a
   few seconds since it runs a few sops decrypt commands)

1. Run `list_inactive_ees_csv` to query and print a list of inactive
   EEs to delete

1. Run `list_inactive_ees_csv | cut -d ',' -f 2 >
   inactive_ee_key_labels.txt` to save a list of key labels to
   delete. It should look something like this:

   ```sh
   $ head inactive_ee_key_labels.txt
   aus-20181015205220
   aus-20181105162523
   ...
   ```

1. Run `set_cloudhsm_env_vars $sops_encrypted_config_file` to decrypt
   and export env vars to access the CloudHSM cluster (this might take
   a few seconds since it runs a few sops decrypt commands)

1. Run `cat inactive_ee_key_labels.txt | ./find_ec_keys_by_label.sh >
   inactive_ee_keys.csv` to find HSM key handles for the given
   labels. (this might take a minute or two since it runs each
   operation as a single key management command) Example output:

   ```sh
   $ cat inactive_ee_key_labels.txt | ./find_ec_keys_by_label.sh > inactive_ee_keys.csv
   public key not found for normandy_cspki-20190520224541
   private key not found for normandy_cspki-20190520224541
   ...
   INFO: success finished searching for EC keys with the provided labels
   $ head inactive_ee_keys.csv
   aus-20181015205220,123456
   aus-20181015205220,123457
   ...
   ```

   Keys deleted from earlier runs will not be found. This is expected.


#### Delete the keys

1. Run `./delete_keys_by_handle.sh < inactive_ee_keys.csv` to print
   keys we will delete (but not delete them yet). Example output:

   ```sh
   $ ./delete_keys_by_handle.sh < inactive_ee_keys.csv
   ...
   got label aus-20181015205220 and handle 123456
   123456
   provided key label aus-20181015205220 matches label aus-20181015205220 for handle 123456
   would delete: 123456 for label aus-20181015205220
   ...
   success! would delete: 42 keys
   ```

1. Inspect the output

1. Run `DRY_RUN=0 ./delete_keys_by_handle.sh < inactive_ee_keys.csv`
   to delete the keys
