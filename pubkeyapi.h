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

struct EPKAInstance;
struct EPKASession;

#define DROPBEAR_EPKA_VERSION_MAJOR     1
#define DROPBEAR_EPKA_VERSION_MINOR     0

/* Creates an instance of the plugin.
 *
 * This is the main entry point of the plug-in and should be IMMUTABLE across
 * different API versions. Dropbear will check the version number
 * returned in the api_version to match the version it understands and reject
 * any plugin for which API major version does not match.
 *
 * If the version MINOR is different, dropbear will allow the plugin to run 
 * only if: plugin_MINOR > dropbear_MINOR
 *
 * If plugin_MINOR < dropbeart_MINOR or if the MAJOR version is different
 * dropbear will reject the plugin and terminate the execution.
 *
 * Returns NULL in case of failure, otherwise a void * of the instance that need
 * to be passed to all the subsequent call to the plugin
 */
typedef struct EPKAInstance *(* PubkeyExtPlugin_newFn)(int verbose, 
        const char *options);
#define DROPBEAR_PUBKEY_PLUGIN_FNNAME_NEW               "plugin_new"


/* Validate a client through public key authentication
 *
 * If session has not been already created, creates it and store it 
 * in *sessionInOut.
 * If session is a non-NULL, it will reuse it.
 *
 * Returns DROPBEAR_SUCCESS (0) if success or DROPBEAR_FAILURE (-1) if
 * authentication fails
 */
typedef int (* PubkeyExtPlugin_checkPubKeyFn)(struct EPKAInstance *pluginInstance,
        struct EPKASession **sessionInOut,
        const char* algo, 
        unsigned int algolen,
        const unsigned char* keyblob, 
        unsigned int keybloblen,
        const char *username);

/* Notify the plugin that auth completed (after signature verification)
 */
typedef void (* PubkeyExtPlugin_authSuccessFn)(struct EPKASession *session);

/* Deletes a session
 * TODO: Add a reason why the session is terminated. See svr_dropbear_exit (in svr-session.c)
 */
typedef void (* PubkeyExtPlugin_sessionDeleteFn)(struct EPKASession *session);

/* Deletes the plugin instance */
typedef void (* PubkeyExtPlugin_deleteFn)(struct EPKAInstance *pluginInstance);


struct EPKAInstance {
    int                             api_version[2];         /* 0=Major, 1=Minor */

    PubkeyExtPlugin_checkPubKeyFn   checkpubkey;            /* mandatory */
    PubkeyExtPlugin_authSuccessFn   auth_success;           /* optional */
    PubkeyExtPlugin_sessionDeleteFn delete_session;         /* mandatory */
    PubkeyExtPlugin_deleteFn        delete_plugin;          /* mandatory */
};

struct EPKASession {
    struct EPKAInstance *  plugin_instance;

    unsigned char * auth_options;                           /* Set to NULL if no options are provided */
    unsigned int    auth_options_length;
};

#endif
