# Description

*pam_ssh* and *libnss_mapiamname* modules enable the user to log in remotely to the server system by using an external IAM authentication system(s).

The main idea is based on using the IAM provider's API to generate/obtain and validate short-term (usually several minutes) token and then to verify one by the *pam_ssh* installed as addidional plugin authentication module (PAM) and then to map username obtained from selected identity provider to a local system username (*libnss_mapiamname*).

Obtaining the token itself is possible in several ways (e.g. following device [flow](https://gist.github.com/andreaceccanti/5b69323b89ce08321e7b5236de503600)) [ways](https://indigo-iam.github.io/docs/v/current/user-guide/getting-a-token.html).
 At the time of login (authentication), the local system starts the process of checking the rules stored in */etc/pam.d/sshd* file (in case of *Ubuntu*). If properly configured, *pam_ssh.so* module will be used as first in the authentication stack.

Working configuration requires that users who will be authenticated using new method need to belong to a  specific system user group (e.g. deep) and all the username mappings need to be stored in */etc/pam_nss.conf* file. This file is commonly used by PAM and NSS. The PAM reads the url address at which the token will be validated, while the NSS provides the mappings.

The full procedure for installing and configuring *pam_ssh* and *libnss_mapiamname* is given in modules’ folders (please keep in mind presented configurations assume that deep user group and releveant local/mapped users have been already created).
