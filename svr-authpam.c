/*
 * Dropbear - a SSH2 server
 * 
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

/* Validates a user password */

#include "includes.h"
#include "session.h"
#include "buffer.h"
#include "dbutil.h"
#include "auth.h"

#if defined(HAVE_SECURITY_PAM_APPL_H)
#include <security/pam_appl.h>
#elif defined (HAVE_PAM_PAM_APPL_H)
#include <pam/pam_appl.h>
#endif

#ifdef DROPBEAR_PAM_AUTH

struct UserDataS {
    char* user;
    char* passwd;
};

/* PAM conversation function */
int 
pamConvFunc(int num_msg, 
	    const struct pam_message **msg,
	    struct pam_response **respp, 
	    void *appdata_ptr) {
  int rc = PAM_SUCCESS;
  struct pam_response* resp = NULL;
  struct UserDataS* userDatap = (struct UserDataS*) appdata_ptr;

  /* tbd only handles one msg */
    
  switch((*msg)->msg_style) {
  case PAM_PROMPT_ECHO_OFF:
    dropbear_log(LOG_DEBUG, "pamConvFunc(): PAM_PROMPT_ECHO_OFF: (*msg)->msg=\"%s\"", (*msg)->msg);

    if (strcmp((*msg)->msg, "Password:") == 0) {
      resp = (struct pam_response*) malloc(sizeof(struct pam_response));
      resp->resp = (char*) strdup(userDatap->passwd);
      /* dropbear_log(LOG_DEBUG, "pamConvFunc(): PAM_PROMPT_ECHO_ON: userDatap->passwd=\"%s\"", userDatap->passwd); */
      resp->resp_retcode = 0;
      (*respp) = resp;
    }
    else {
      dropbear_log(LOG_WARNING, "pamConvFunc(): PAM_PROMPT_ECHO_OFF: unrecognized prompt, (*msg)->msg=\"%s\"", (*msg)->msg);
      rc = PAM_CONV_ERR;
    }
    break;
  case PAM_PROMPT_ECHO_ON:
    dropbear_log(LOG_DEBUG, "pamConvFunc(): PAM_PROMPT_ECHO_ON: (*msg)->msg=\"%s\"", (*msg)->msg);

    if ((strcmp((*msg)->msg, "login: " ) == 0) || (strcmp((*msg)->msg, "Please enter username: " ) == 0)) {
      resp = (struct pam_response*) malloc(sizeof(struct pam_response));
      resp->resp = (char*) strdup(userDatap->user);
      dropbear_log(LOG_DEBUG, "pamConvFunc(): PAM_PROMPT_ECHO_ON: userDatap->user=\"%s\"", userDatap->user);
      resp->resp_retcode = 0;
      (*respp) = resp;
    }
    else {
      dropbear_log(LOG_WARNING, "pamConvFunc(): PAM_PROMPT_ECHO_ON: unrecognized prompt, (*msg)->msg=\"%s\"", 
		   (*msg)->msg);
      rc = PAM_CONV_ERR;
    }
    break;
  case PAM_ERROR_MSG:
    dropbear_log(LOG_DEBUG, "pamConvFunc(): PAM_ERROR_MSG: (*msg)->msg=\"%s\"", (*msg)->msg);
    /* printf("error msg: '%s'\n", (*msg)->msg); */
    rc = PAM_CONV_ERR;
    break;
  case PAM_TEXT_INFO:
    dropbear_log(LOG_DEBUG, "pamConvFunc(): PAM_TEXT_INFO: (*msg)->msg=\"%s\"", (*msg)->msg);
    /* printf("text info: '%s'\n", (*msg)->msg); */
    rc = PAM_CONV_ERR;
    break;
  case PAM_RADIO_TYPE:
    dropbear_log(LOG_DEBUG, "pamConvFunc(): PAM_RADIO_TYPE: (*msg)->msg=\"%s\"", (*msg)->msg);
    /* printf("radio type: '%s'\n", (*msg)->msg); */
    rc = PAM_CONV_ERR;
    break;
  case PAM_BINARY_PROMPT:
    dropbear_log(LOG_DEBUG, "pamConvFunc(): PAM_BINARY_PROMPT: (*msg)->msg=\"%s\"", (*msg)->msg);
    /* printf("binary prompt: '%s'\n", (*msg)->msg); */
    rc = PAM_CONV_ERR;
    break;
  default:
    dropbear_log(LOG_DEBUG, "pamConvFunc(): Unknown PAM message");
    /* printf("unknown message\n"); */
    rc = PAM_CONV_ERR;
    break;      
  }

  return rc;
}

/* Process a password auth request, sending success or failure messages as
 * appropriate */
void svr_auth_pam() {
  // PAM stuff
  int rc = PAM_SUCCESS;
  struct UserDataS userData;
  struct pam_conv pamConv = {
    pamConvFunc,
    &userData /* submitted to pamvConvFunc as appdata_ptr */ 
  };
  pam_handle_t* pamHandlep = NULL;
  unsigned char * password = NULL;
  unsigned int passwordlen;

  unsigned char changepw;

  /* check if client wants to change password */
  changepw = buf_getbyte(ses.payload);
  if (changepw) {
    /* not implemented by this server */
    send_msg_userauth_failure(0, 1);
    return;
  }

  password = buf_getstring(ses.payload, &passwordlen);

  /* clear the buffer containing the password */
  buf_incrpos(ses.payload, -passwordlen - 4);
  m_burn(buf_getptr(ses.payload, passwordlen + 4), passwordlen + 4);

  /* used to pass data to the PAM conversation function */
  userData.user = ses.authstate.printableuser;
  TRACE(("user is %s\n", userData.user));
  userData.passwd = password;

  /* Init pam */
  if ((rc = pam_start("sshd", NULL, &pamConv, &pamHandlep)) != PAM_SUCCESS) {
    dropbear_log(LOG_WARNING, "pam_start() failed, rc=%d, %s\n", rc, pam_strerror(pamHandlep, rc));
    /* fprintf(stderr, "pam_start() failed, rc=%d, %s\n", rc, pam_strerror(pamHandlep, rc)); */
    goto clean;
  }
  
  /*
  if ((rc = pam_set_item(pamHandlep, PAM_RHOST, webReqp->ipaddr) != PAM_SUCCESS)) {
    dropbear_log(LOG_WARNING, "pam_set_item() failed, rc=%d, %s\n", rc, pam_strerror(pamHandlep, rc));
    return;
  }
  */
  
  /* just to set it to something */
  if ((rc = pam_set_item(pamHandlep, PAM_TTY, "ssh") != PAM_SUCCESS)) {
    dropbear_log(LOG_WARNING, "pam_set_item() failed, rc=%d, %s\n", rc, pam_strerror(pamHandlep, rc));
    goto clean;
  }
  
  (void) pam_fail_delay(pamHandlep, 0 /* musec_delay */);
 
  /* (void) pam_set_item(pamHandlep, PAM_FAIL_DELAY, (void*) pamDelayFunc); */
  
  if ((rc = pam_authenticate(pamHandlep, 0)) != PAM_SUCCESS) {
    dropbear_log(LOG_WARNING, "pam_authenticate() failed, rc=%d, %s\n", rc, pam_strerror(pamHandlep, rc));
    /* fprintf(stderr, "pam_authenticate() failed, rc=%d, %s\n", rc, pam_strerror(pamHandlep, rc)); */
    dropbear_log(LOG_WARNING,
		 "bad pam password attempt for '%s'",
		 ses.authstate.printableuser);
    send_msg_userauth_failure(0, 1);
    goto clean;
  }

  if ((rc = pam_acct_mgmt(pamHandlep, 0)) != PAM_SUCCESS) {
    dropbear_log(LOG_WARNING, "pam_acct_mgmt() failed, rc=%d, %s\n", rc, pam_strerror(pamHandlep, rc));
    /* fprintf(stderr, "pam_acct_mgmt() failed, rc=%d, %s\n", rc, pam_strerror(pamHandlep, rc)); */
    dropbear_log(LOG_WARNING,
		 "bad pam password attempt for '%s'",
		 ses.authstate.printableuser);
    send_msg_userauth_failure(0, 1);
    goto clean;
  }

  /* successful authentication */
  dropbear_log(LOG_NOTICE, 
	       "password auth succeeded for '%s'",
	       ses.authstate.printableuser);
  send_msg_userauth_success();
  
 clean:
  if (password != NULL) {
    m_burn(password, passwordlen);
    m_free(password);
  }
  if (pamHandlep != NULL) {
    (void) pam_end(pamHandlep, 0 /* pam_status */);
  }
}

#endif /* DROPBEAR_PAM_AUTH */
