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
#ifndef DROPBEAR_PUBKEY_H
#define DROPBEAR_PUBKEY_H


/* Function API */

/* Creates an instance
 * Returns NULL in case of failure, otherwise a void * of the instance that need
 * to be passed to all the subsequent call to the plugin
 */
typedef void *(* PubkeyExtPlugin_newFn)(int verbose, 
        const char *options);
#define DROPBEAR_PUBKEY_PLUGIN_FNNAME_NEW               "plugin_new"


/* Validate a client through public key authentication
 * Returns a new session (opaque pointer to be destroyed when session ends)
 * or NULL in case of authentication failure.
 *
 * TODO: Have a way to pass options to the caller
 */
typedef void * (* PubkeyExtPlugin_checkPubKeyFn)(void *pluginInstance, 
        const char* algo, 
        unsigned int algolen,
        const unsigned char* keyblob, 
        unsigned int keybloblen);
#define DROPBEAR_PUBKEY_PLUGIN_FNNAME_CHECKPUBKEY       "plugin_checkpubkey"

/* Notify the plugin that auth completed (after signature verification)
 */
typedef void (* PubkeyExtPlugin_authSuccessFn)(void *pluginInstance, void *sessionInstance);
#define DROPBEAR_PUBKEY_PLUGIN_FNNAME_AUTHSUCCESS       "plugin_auth_success"

/* Deletes a session
 * TODO: Add a reason why the session is terminated. See svr_dropbear_exit (in svr-session.c)
 */
typedef void (* PubkeyExtPlugin_sessionDeleteFn)(void *pluginInstance,
        void *pluginSession);
#define DROPBEAR_PUBKEY_PLUGIN_FNNAME_SESSIONDELETE     "plugin_session_delete"

/* Deletes the plugin instance */
typedef void (* PubkeyExtPlugin_deleteFn)(void *pluginInstance);
#define DROPBEAR_PUBKEY_PLUGIN_FNNAME_DELETE            "plugin_delete"

#endif
