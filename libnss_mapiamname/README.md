# NSS library

This library can be used for mapping IAM username to local system user.

# Example

1. Compile the source.

```bash
$ make && sudo make install
```

Library will be installed in `/lib` folder.

## Using the library

2. Open at least a single session with *root* user logged in for security. 
3. Edit  */etc/nsswitch.conf* by replacing

```bash
passwd:         files
```

with

```bash
passwd:         files nis compat mapiamname
```


4.  Edit  */etc/pam_nss.conf* by adding mappings for all required IAM->localuser name in the following format

```bash
mappings = ({ name = "deep";
              url = "https://iam.deep-hybrid-datacloud.eu/userinfo";
              users = ( { from  = "user1";
                          to = "deep_user1"; },
                        { from  = "user2";
                         to = "deep_user2"; }
                      )
            },
            { name = "cracow";
              url = "https://iam.deep-hybrid-datacracow.eu/userinfo";
              users = ( { from  = "user1";
                          to = "cracow_user1"; },
                        { from  = "user2";
                          to = "cracow_user2"; },
                        { from  = "user3";
                          to = "cracow_users"; }
                      )
           }
          );

```

5. All changes take effect immediatelly. In case something is wrong please use *root* console and undo changes in the *nsswitch.conf* file.
All *local** users in order to be mapped and correctly authenticated must belong to a group name described in *common-** files.
