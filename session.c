#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <multitask.h>
#include <inttypes.h>
#include <unistd.h>
#include "nikolav2g_0.9.4.h"
#include "map.h"

Map session_map;
QLock session_map_mutex;

static size_t hash(Key k)
{
    return (size_t) k.u64 & 0xFFFFFFFF;
}

static int cmp(Key k1, Key k2)
{
    if (k1.u64 == k2.u64) {
        return 0;
    }
    return -1;
}

int gen_random_data(void *dest, size_t dest_len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    int len = 0;
    if (fd == -1) {
        if (chattyv2g) fprintf(stderr, "%s: %m\n", "gen_random_data: open /dev/urandom");
        return -1;
    }
    while (len < dest_len) {
        ssize_t result = read(fd, (char*)dest + len, dest_len - len);
        if (result < 0) {
            if (chattyv2g) fprintf(stderr, "%s: %m\n", "gen_random_data: read");
            close(fd);
            return -1;
        }
        len += result;
    }
    close(fd);
    return 0;
}

void session_lock(session_t *session)
{
    if (session == NULL) {
        return;
    }
    qlock(&session->mutex);
}
void session_unlock(session_t *session)
{
    if (session == NULL) {
        return;
    }
    qunlock(&session->mutex);
}

int init_sessions()//
{
    int err = mapinit(&session_map,
             sizeof(session_t*),
             256,
             &hash,
             &cmp);
    if (err == -1) {
        printf("main: map_create failed\n");
        return -1;
    }
    memset(&session_map_mutex, 0, sizeof(session_map_mutex));
    return 0;
}

session_t *session_lookup(uint64_t sessionid)
{
    if (sessionid == 0) {
        return NULL;
    }
    union Key k = {.u64 = sessionid};
    qlock(&session_map_mutex);
    session_t **sessionpp =  (session_t**)mapfind(&session_map, k);
    if (sessionpp == NULL) {
        printf("session_lookup: invalid session\n");
        return NULL;
    }
    session_lock(*sessionpp);
    (*sessionpp)->refcount++;
    if ((*sessionpp)->refcount > 4) {
        printf("session_lookup: %d references to the same session, code error is likely\n", (*sessionpp)->refcount);
    }
    session_unlock(*sessionpp);
    qunlock(&session_map_mutex);

    return *sessionpp;
}

session_t *session_new(size_t session_data_size, void (*data_cleanup)(session_t *))
{
    union Key k;
    // Must be hex binary
    int err = gen_random_data(&k.u64, 8);
    if (err != 0) {
        return NULL;
    }
    qlock(&session_map_mutex);
    session_t **sessionpp = (session_t**)mapinsert(&session_map, k);
    if (sessionpp == NULL) {
        return NULL;
    }
    *sessionpp = malloc(sizeof(session_t) + session_data_size);
    if (*sessionpp == NULL) {
        return NULL;
    }
    memset(*sessionpp, 0, sizeof(session_t) + session_data_size);
    qunlock(&session_map_mutex);
   //(*sessionpp)->tls_enabled = tls_enabled;
    (*sessionpp)->id = k.u64;
    (*sessionpp)->status = SESSION_ACTIVE;
    (*sessionpp)->refcount = 1;
    (*sessionpp)->data_cleanup = data_cleanup;
    return *sessionpp;
}


session_t *session_lookup_exi(struct iso1EXIDocument *exiIn) // Modified by JJS (2019.02.07)
{
    uint64_t sessionid;
    memcpy(&sessionid, exiIn->V2G_Message.Header.SessionID.bytes, 8);
    return session_lookup(sessionid);
}


void session_terminate(session_t *session)
{
    union Key k = { .u64 = session->id };
    qlock(&session_map_mutex);
    mapremove(&session_map, k);
    session->status = SESSION_TERMINATED;
    qunlock(&session_map_mutex);
}

void session_pause(session_t *session, bool pause)
{
    session->status = SESSION_PAUSED;
}

void session_remove_ref(session_t *session)
{
    if (session == NULL) {
        return;
    }
    session_lock(session);
    session->refcount--;
    if (session->refcount == 0 && session->status == SESSION_TERMINATED) {
        if (session->data_cleanup != NULL) {
            session->data_cleanup(session);
        }
        free(session);
        if (chattyv2g) fprintf(stderr, "Succesfully freed session\n");
        // No need to unlock if refcount 0, since it can never increase from this point since it has been removed from the map.
    } else if (session->refcount < 0) {
        if (chattyv2g) fprintf(stderr, "session_remove_ref: Negative session ref-count. THIS IS BAD!\n");
    } else {
        session_unlock(session);
    }
}
