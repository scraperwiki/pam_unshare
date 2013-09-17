/******************************************************************************
 * A module for Linux-PAM that will set the default namespace after
 * establishing a session via PAM.
 *
 * (C) Copyright IBM Corporation 2005
 * (C) Copyright Red Hat 2006
 * (C) Copyright Louis-Dominique Dubeau 2008
 * All Rights Reserved.
 *
 * Written by: Louis-Dominique Dubeau
 *             on the basis of pam_namespace (see there
 *             for credits). 
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * on the rights to use, copy, modify, merge, publish, distribute, sub
 * license, and/or sell copies of the Software, and to permit persons to whom
 * the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT.  IN NO EVENT SHALL
 * IBM AND/OR THEIR SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#define _GNU_SOURCE
#include <stdlib.h>

#include <sched.h>
#include <syslog.h>
#include <security/pam_modules.h>

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

/*
 * Entry point from pam_open_session call.
 */
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
                                   int argc, const char **argv)
{
    /* Parse arguments. */
    if (argc < 1) {
       	pam_syslog(pamh, LOG_ERR, "usage: pam_unshare.so [group name]");
	return PAM_SESSION_ERR;
    }

    pam_syslog(pamh, LOG_INFO, "Getting PAM_USER");
    /* See http://www.linux-pam.org/Linux-PAM-html/mwg-expected-by-module-item.html */
    const void *item_v;
    int rc = pam_get_item(pamh, PAM_USER, &item_v);
    const char *username = "didn't get user";
    if(rc == PAM_SUCCESS) {
        username = item_v;
    }
    syslog(LOG_INFO, "pam_unshare, return code %d, found user %s", rc, username);

    struct passwd* user = getpwnam(username);
    if (user == NULL) {
        pam_syslog(pamh, LOG_ERR, "getpwnam(%s) == NULL", username);
	return PAM_SESSION_ERR;
    }
    struct group* group = getgrgid(user->pw_gid);
    if (group == NULL) {
        pam_syslog(pamh, LOG_ERR, "getgrgid(%d) == NULL", user->pw_gid);
	return PAM_SESSION_ERR;
    }
    
    const char* target_group = argv[0];

    if (strcmp(target_group, group->gr_name) == 0) {
	pam_syslog(pamh, LOG_INFO, "found user in databox! calling unshare()");

	if(unshare(CLONE_NEWNS) < 0) {
            pam_syslog(pamh, LOG_ERR, "Unable to unshare from parent namespace, %m");
            return PAM_SESSION_ERR;
	}
    }

    return PAM_SUCCESS;
}


/*
 * Entry point from pam_close_session call.
 */
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
                                    int argc, const char **argv)
{
    syslog(LOG_INFO, "unshare close session, flags %08x\n", (unsigned int)flags);
    /* Parse arguments. */
    if (argc > 0) {
       	pam_syslog(pamh, LOG_ERR,
	    "pam_unshare does not take any arguments");
	return PAM_SESSION_ERR;
    }

    return PAM_SUCCESS;
}
