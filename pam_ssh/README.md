# PAM ssh

This application can be used to test a PAM stack for authentication with IAM.

# Example

1. Compile the source.

```bash
$ make && sudo make install
```

Library will be installed in */lib/security* folder.

## Using the library

If we want all users belonging to `deep` group be authenticated by IAM, then:

2. Edit  */etc/pam.d/common-auth* by adding 

```bash
auth  [default=1 success=ignore] pam_succeed_if.so quiet user ingroup deep
auth   sufficient pam_ssh.so pam_nss_conf=/etc/pam_nss.conf
```
as first authentication rules

3.  Edit  */etc/pam.d/common-account* by adding

```bash
account  [default=1 success=ignore] pam_succeed_if.so quiet user ingroup deep
account   sufficient pam_ssh.so pam_nss_conf=/etc/pam_nss.conf
```
as first accounting rules

4.  Edit  */etc/pam.d/common-session* and */etc/pam.d/common-session-noninteractive* by adding

```bash
session  [default=1 success=ignore] pam_succeed_if.so quiet user ingroup deep
session   sufficient pam_ssh.so pam_nss_conf=/etc/pam_nss.conf
```
as rights after the first rule

```bash
session [default=1]              pam_permit.so
```

5. Restart ssh daemon

```bash
sudo service sshd restart
```
