/*******************************************************************************
 * file:        pam_ssh.c
 * author:      damian kaliszan based on ben servoz's source code
 * description: PAM module to provide IAM authentication
 * notes:       Using original code at http://ben.akrin.com/?p=1068
 * notes :      MicroJSON https://gitlab.com/esr/microjson/tree/master
 * tests:        https://github.com/pbrezina/pam-test
*******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <curl/curl.h>
#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include "mjson.h"
#include "pam_ssh_common.h"
#include "../common/common.h"

#if !CURL_AT_LEAST_VERSION(7, 62, 0)
#error "This library requires curl 7.62.0 or later"
#endif

/*
* note: libcurl has to be compiled & build with --with-ssl version enabled!
*/

/*
 setcap or sudo needed for pam_test
https://unix.stackexchange.com/questions/318625/how-to-grant-a-user-rights-to-change-ownership-of-files-directories-in-a-directo
*/

/* the function to invoke as the data recieved */
size_t static callback_func(void *buffer,
                        size_t size,
                        size_t nmemb,
                        void *userp)
{
    char **resp =  (char**)userp;
    /* assuming the response is a string */
    *resp = strndup(buffer, (size_t)(size *nmemb));
    return size * nmemb;
}


static
int my_trace(CURL *handle, curl_infotype type,
             char *data, size_t size,
             void *userp) {
    const char *text;
    (void)handle; /* prevent compiler warning */
    (void)userp;
   

    switch (type) {
        case CURLINFO_TEXT:
            sys_log(LOG_DEBUG, "== Info: %s", data);
        default: /* in case a new one is introduced to shock us */
            return 0;
 
        case CURLINFO_HEADER_OUT:
            text = "=> Send header";
            break;
        case CURLINFO_DATA_OUT:
            text = "=> Send data";
            break;
        case CURLINFO_SSL_DATA_OUT:
            text = "=> Send SSL data";
            break;
        case CURLINFO_HEADER_IN:
            text = "<= Recv header";
            break;
        case CURLINFO_DATA_IN:
            text = "<= Recv data";
            break;
        case CURLINFO_SSL_DATA_IN:
            text = "<= Recv SSL data";
            break;
    }
  return 0;
}


// expected hook
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
    return PAM_SUCCESS ;
}


// this function is ripped from pam_unix/support.c, it lets us do IO via PAM
int converse( pam_handle_t *pamh, int nargs, struct pam_message **message, struct pam_response **response ) {
    int retval ;
    struct pam_conv *conv ;

    retval = pam_get_item( pamh, PAM_CONV, (const void **) &conv ) ; 
    if( retval==PAM_SUCCESS ) {
        retval = conv->conv( nargs, (const struct pam_message **) message, response, conv->appdata_ptr ) ;
    }

    return retval ;
}


/*
 * Authenticate with user token to IAM
 * input: input token
 * host_endpoint: where to authenticate
 * response: output response
 * err: error if occures, NULL otherwise
 */

static long http_auth(const char* input, const char* host_endpoint, char** response, char** err){
    // HTTP request to service that will dispatch the code
    CURL *curl ;
    struct curl_slist *headers = NULL;
    CURLcode res = CURLE_COULDNT_CONNECT;
    char error[CURL_ERROR_SIZE];
    char* resp = NULL;
    long http_code = 404;
    int cnt;
    curl = curl_easy_init() ;
    if (curl) {
        int len = strlen(AUTH_BEARER) + strlen(input) + 1; 
        char auth_bearer[len] ;
        //strcpy(auth_bearer, AUTH_BEARER);
        //strcat(auth_bearer, input) ;
        cnt = snprintf(auth_bearer, len, "%s%s", AUTH_BEARER, input );
        if (cnt < 1) return http_code;
        headers = curl_slist_append( headers, auth_bearer);
        curl_easy_setopt(curl, CURLOPT_URL, host_endpoint) ;
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L );
        curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
        curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, my_trace);
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback_func);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
        error[0] = 0;
        res = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        curl_easy_cleanup(curl);
    }
//    sys_log(LOG_DEBUG, "response: %s", resp);
//    sys_log(LOG_DEBUG, "error: %s", error);
    if (resp){
            if (*response){            
            if (strlen(resp) != strlen(*response))
                *response = realloc(*response, sizeof(char) * (strlen(resp) + 1));
            cnt = snprintf(*response, strlen(resp) + 1, "%s", resp);
            if (cnt < 1) 
                return http_code;
        } else
            *response = strdup(resp);
    }
    if (error){
        if (*err){
            if (CURL_ERROR_SIZE != strlen(*err))
                *err = realloc(*err, sizeof(char) * (CURL_ERROR_SIZE + 1));                
            cnt = snprintf(*err, CURL_ERROR_SIZE + 1, "%s", error);
            if (cnt < 1)
                return http_code;
        } else
            *err = strdup(error);
    }
    sys_log(LOG_DEBUG, "response: %s", *response);
    sys_log(LOG_DEBUG, "err: %s", *err);
    if (headers)
        free(headers);
    if (resp)
        free(resp);
    return http_code;
}

// expected hook, this is where custom stuff happens
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
    int retval ;
    int i ;
    const char *provided_username;
    char *user_location = NULL;
    char *user_endpoint = NULL;
    char *user_url = NULL;
    char* host_endpoint = NULL;
    char *host_url = NULL;
    char *username = NULL;
    int status = PAM_AUTH_ERR;
    char *input = NULL;
    
    struct pam_message msg[1], *pmsg[1];
    struct pam_response *resp;
    //int* errnop = (int*)calloc(1, sizeof(int));
    int errnop;
    // retrieving parameters
    char pam_nss_conf[BUF_SIZE];    

    char* error = (char*)calloc(CURL_ERROR_SIZE, sizeof(char));
    char* response = NULL;//(char*)calloc(10, sizeof(char));

    
    //sys_log(LOG_DEBUG, "argc: %d", argc );

    // No config file provided
    if (argc != 1)
        return PAM_AUTH_ERR;        

    if (!strncmp(argv[0], CONF_VAR_NAME, strlen(CONF_VAR_NAME))){
        strncpy(pam_nss_conf, argv[0] + strlen(CONF_VAR_NAME), BUF_SIZE);
    } else
        return PAM_AUTH_ERR;

    if (!mapped_users){
        int map_ret = map_init_common(&errnop, pam_ssh);
        if (map_ret){        
            if (errnop == ENOENT){
                //reset_config();
                //return PAM_AUTH_ERR;
                goto error;
            }
        }    
    }
    if (!mapped_users) {
        goto error;
    }
    if ((retval = pam_get_item( pamh, PAM_USER, (const void **)& provided_username)) != PAM_SUCCESS) {
        sys_log(LOG_ERR, "Error: %s", pam_strerror( pamh, retval ) );
        goto error;        
    }

    if (!provided_username)
        goto error;
    username = strdup(provided_username);
    user_location = strdup(provided_username);

    if (traverse_username(provided_username, &username, &user_location)){
        sys_log(LOG_DEBUG, "username: %s", username);    
        sys_log(LOG_DEBUG, "user_location: %s", user_location);
        if (user_location){            
            // PAM has to fetch URL from NSS config...
            user_endpoint = map_get_url_for_location(user_location);            
        } else    {
            user_endpoint = map_get_mapped_user(username, USED_IN_PAM);
        }
        //sys_log(LOG_DEBUG, "user_endpoint: %s", user_endpoint);
        if (!user_endpoint) 
            goto error;
        user_url = strdup(user_endpoint);
        if (!traverse_url(user_endpoint, &user_url)){
            if (user_endpoint)
                free(user_endpoint);
            goto error;
        }
    } else 
           goto error;

    struct mapitem* mapped_item = (struct mapitem*)map_get_key(user_location, mapped_users);
    if (user_location)
           free(user_location);
    if (!mapped_item)
           goto error;
       
    host_endpoint = strdup(mapped_item->url);
    if (!host_endpoint)
        goto error;        
    host_url = strdup(mapped_item->url);
    if (!traverse_url(host_endpoint, &host_url)){
        if (host_url){
            free(host_endpoint);
            free(host_url);
        }            
        goto error;
    }
    if (!host_url)
        goto error;
    if (strcmp(user_url, host_url) != 0) 
        goto error;
    sys_log(LOG_DEBUG,"Free user_url");
    if (user_url)
        free(user_url);
    sys_log(LOG_DEBUG,"user_url freed");
    // setting up conversation call prompting for one-time code
    pmsg[0] = &msg[0] ;
    msg[0].msg_style = PAM_PROMPT_ECHO_ON ;
    const char prompt[15] = "Access token: ";
/*
    char prompt[256] = "Access token [";
    strcat(prompt, host_endpoint);
    strcat(prompt, "]: ");        
*/
    sys_log(LOG_DEBUG, "%s", prompt);
    msg[0].msg = prompt;
    
    resp = NULL ;
    if ((retval = converse(pamh, 1, pmsg, &resp)) != PAM_SUCCESS)
        // if this function fails, make sure that ChallengeResponseAuthentication in sshd_config is set to yes            
        goto error;
    // retrieving user input
    if (resp) {
        if ((flags & PAM_DISALLOW_NULL_AUTHTOK) && resp[0].resp == NULL) {
            free(resp);
            goto error;
        }
        input = resp[0].resp;        
        resp[0].resp = NULL; 
        if (strstr(input, INCORRECT))
            goto error;
    } else
        goto error;
    sys_log(LOG_DEBUG, "Token provided");

    // authenticate with token (input)
    long http_code = http_auth(input, host_endpoint, &response, &error);    

    // Check HTTP auth code
    if (http_code < 200 || http_code >= 300) {
        sys_log(LOG_ERR, "HTTP request failed: error code %ld (%s)", http_code, error);
    } else {        
        struct userinfo my_info;
           // Call object parsing function
        
    if (json_userinfo_read(response, &my_info) == 0) {
            sys_log(LOG_DEBUG,"Username from OpenID provider: %s", my_info.name);
            sys_log(LOG_DEBUG,"OpenID preferred_username: %s", my_info.preferred_username);
            sys_log(LOG_DEBUG,"Username: %s", username);
            status = (strcmp(username, my_info.preferred_username) == 0)? PAM_SUCCESS: PAM_AUTH_ERR;                
        }
    }
    // Free HTTP call response structures
    if (map_debug > 2)
        sys_log(LOG_ERR, "free response");
    if (response)
        free(response);
    
    if (map_debug > 2)
        sys_log(LOG_ERR, "free error");
    if (error)
        free(error);

    // Free input when talking to PAM module
    if (map_debug > 2)
        sys_log(LOG_ERR, "free input");
    if (input)
        free(input);
    
    if (map_debug > 2)
        sys_log(LOG_ERR, "free host_endpoint");
    if (host_endpoint) 
        free(host_endpoint);
    
    if (map_debug > 2)
        sys_log(LOG_ERR, "free host_url");
    if (host_url)
        free(host_url);
    
    error:
        if (map_debug > 2)
            sys_log(LOG_ERR, "free username");
        if (username)
            free(username);
        
        if (map_debug > 2)
            sys_log(LOG_ERR, "free user_location");
        if (user_location)
            free(user_location);
        
        if (map_debug > 2)
            sys_log(LOG_ERR, "free user_url");
        if (user_url)
            free(user_url);
        
        if (map_debug > 2)
            sys_log(LOG_ERR, "free mapped_users");
        if (mapped_users)
            map_close(&mapped_users);
        if (map_debug > 2)
             sys_log(LOG_ERR, "free mapped_users OK; %d", mapped_users!= NULL? 1:0);
        
        if (map_debug > 2)
            sys_log(LOG_ERR, "free excluded_users");
        if (excluded_users) 
            list_close(&excluded_users);
        if (map_debug > 2)
            sys_log(LOG_ERR, "free excluded_users OK; %d", excluded_users!= NULL? 1:0);
    if (map_debug > 1)
        sys_log(LOG_ERR, "Returning %d", status);
    return status;

}


PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const char *user = NULL, *serwis = NULL;
    int ret;
    if((ret = pam_get_user(pamh, &user, "Login: ")) != PAM_SUCCESS){
        sys_log(LOG_ERR,"No username found (ACCOUNT section)\n");
        return ret;
    }
    sys_log(LOG_DEBUG, "pam_sm_acct_mgmt username: %s", user);
    if((ret = pam_get_item(pamh, PAM_SERVICE, (const void **)&serwis)) != PAM_SUCCESS){
        sys_log(LOG_ERR ,"No service name (ACCOUNT section)\n");
            return ret;
    }
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
    const char *user = NULL;
    int ret;
    if((ret = pam_get_user(pamh, &user, "Login: ")) != PAM_SUCCESS){
        sys_log(LOG_ERR,"No username found (ACCOUNT section)\n");
        return ret;
    }
    sys_log(LOG_DEBUG, "pam_sm_open_session username: %s", user);
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
    int retval;
    char pname[BUFSIZ];
    const char *username;
    sys_log(LOG_DEBUG, "pam_sm_close_session");    
    if( ( retval = pam_get_item( pamh, PAM_USER, (const void **)& username) ) != PAM_SUCCESS ) {
        sys_log(LOG_ERR, "Error: %s", pam_strerror( pamh, retval ) );
        return retval;
    }
    sys_log(LOG_DEBUG, "pam_sm_close_session username: %s", username);
    if (!username )
        return PAM_AUTH_ERR;  
}
