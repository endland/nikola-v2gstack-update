#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <nikolav2g_0.9.4.h>
#include <mbedtls/x509.h>
#include <mbedtls/error.h>
#include <OpenV2G_0.9.4/iso1EXIDatatypes.h> // Modified by JJS (2019.02.07)
#include "slac/plc_eth.h"
#include "slac/slacassoc.h"
#include "client.h"
#include "server.h"
#include "timeprofiling.h"
#include "can.h" // Added by JJS (2019.02.19)


void plgp_slac_listen(const char *if_name, const uint8_t dest_mac_evse[6]);

static const uint8_t EVMAC[6] = {0x00, 0x05, 0xB6, 0x01, 0x86, 0xBD};
static const uint8_t EVSEMAC[6] = {0x00, 0x05, 0xB6, 0x01, 0x88, 0xA3};

static const char *argv0;

static void fatal(const char *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s: ", argv0);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");

    exit(1);
}

static void ev(const char *if_name, bool tls_enabled, char *can_if_name) // Modified by JJS (2019.02.19)
{
    evcc_conn_t conn;
    ev_session_t s;
    tlog tl;
	float delay = 0.0; // Added by JJS (2019.02.23)
    memset(&conn, 0, sizeof(evcc_conn_t));
    memset(&s, 0, sizeof(s));
    int err;
    int ncycles = 0;
    if (load_contract("certs/contractchain.pem", "certs/contract.key", &s) != 0) {
        fatal("can't load certs/contract.key: %m");
    }
    tl_init(&tl, "ISO 15118 Post SLAC Communication Timings");
    if (chattyv2g) printf("Starting sdp:\n");
    if (ev_sdp_discover_evse(if_name, &conn.addr, tls_enabled) < 0) {
        fatal("failed to discover EVSE on interface %s", if_name);
    }
    tl_register(&tl, "SDP");
	sleep(delay); // Added by JJS (2019.02.23)
    if (chattyv2g) printf("connecting to secc\n");
    if (tls_enabled) {
        err = evcc_connect_tls(&conn, "certs/ev.pem", "certs/ev.key", can_if_name);
    } else {
        err = evcc_connect_tcp(&conn);
    }
    if (err != 0) {
        printf("main: evcc_connect_tls error\n");
        return;
    }
	sleep(delay); // Added by JJS (2019.02.23)
    tl_register(&tl, "Connection & apphandshake");
    if (chattyv2g) printf("session setup request\n");
    err = session_request(&conn, &s);
    if (err != 0) {
        printf("RIP session_request\n");
        return;
    }
	sleep(delay); // Added by JJS (2019.02.23)
    tl_register(&tl, "Session req");
    if (chattyv2g) printf("service discovery request\n");
    err = service_discovery_request(&conn, &s);
    if (err != 0) {
        printf("ev_example: service discovery request err\n");
        return;
    }
	sleep(delay); // Added by JJS (2019.02.23)
    tl_register(&tl, "Service disc. req");
    if (chattyv2g) printf("payment selection request\n");
    err = payment_selection_request(&conn, &s);
    if (err != 0) {
        printf("ev_example: payment_selection_request err\n");
        return;
    }
	sleep(delay); // Added by JJS (2019.02.23)
    tl_register(&tl, "Payment select. req");
    if (chattyv2g) printf("payment details request\n");
    if (!s.charging_is_free) {
        err = payment_details_request(&conn, &s);
        if (err != 0) {
            printf("ev_example: payment_details_request err\n"); // Modified by JJS (2019.02.02)
            return;
        }
    }
	sleep(delay); // Added by JJS (2019.02.23)
    tl_register(&tl, "Payment details req");
    if (chattyv2g) printf("authorization request\n");
    err = authorization_request(&conn, &s);
    if (err != 0) {
        printf("ev_example: authorization_request err\n");
        return;
    }
	sleep(delay); // Added by JJS (2019.02.23)
    tl_register(&tl, "Auth. req");
    if (chattyv2g) printf("charge parameter request\n");
    charging_negotiation:
    err = charge_parameter_request(&conn, &s);
    if (err != 0) {
        printf("ev_example: charge_parameter_request err\n");
        return;
    }
	sleep(delay); // Added by JJS (2019.02.23)
    tl_register(&tl, "Charge param. req");
    if (chattyv2g) printf("power delivery request\n");
    err = power_delivery_request(&conn, &s, iso1chargeProgressType_Start); // Modified by JJS (2019.02.07)
    if (err != 0) {
        printf("ev_example: power_delivery start request err\n");
        return;
    }
	sleep(delay); // Added by JJS (2019.02.23)
    tl_register(&tl, "Power deliv. req");
    if (chattyv2g) printf("Charging (repeating charging status requests)\n");
    for (;ncycles < 5; ncycles++) {
        err = charging_status_request(&conn, &s);
        if (err != 0) {
            printf("ev_example: charging_status_request err\n");
            return;
        }
        tl_register(&tl, "Charging status req");
        if (s.evse_notification == iso1EVSENotificationType_StopCharging) { // Modified by JJS (2019.02.07)
            printf("ev_example: EVSE has prompted charging to stop\n");
            break;
        } else if (s.evse_notification == iso1EVSENotificationType_ReNegotiation) { // Modified by JJS (2019.02.07)
            goto charging_negotiation;
        }
        printf("=");
        fflush(stdout);
        if (enable_timeprofiling) {
            break;
        }
        sleep(1);
    }
    if (chattyv2g) printf("Performing power delivery stop request\n");
    err = power_delivery_request(&conn, &s, iso1chargeProgressType_Stop); // Modified by JJS (2019.02.07)
    if (err != 0) {
        printf("ev_example: power_delivery_request err\n");
        return;
    }
	sleep(delay); // Added by JJS (2019.02.23)
    tl_register(&tl, "Power delivery stop req");
    if (chattyv2g) printf("Performing session stop request\n");
    err = session_stop_request(&conn, &s);
    if (err != 0) {
        printf("ev_example: session_stop_request err\n");
        return;
    }
	sleep(delay); // Added by JJS (2019.02.23)
    tl_register(&tl, "Session stop req");
    tl_print(&tl);
    evcc_close_conn(&conn);
    evcc_session_cleanup(&s);
    if (chattyv2g) printf("Succesfully finished charging, ending session\n");
}

static void evse(const char *if_name, const char *can_if_name)
{
    int tls_port, tcp_port, tls_sockfd, tcp_sockfd;

    // Init the contract root certificates
    int err = mbedtls_x509_crt_parse_path(&Trusted_contract_rootcert_chain,
                                  "certs/root/mobilityop/certs/");
    if (err != 0) {
        printf("evse_example: Unable to load contract root certificates\n");
        char strerr[256];
        mbedtls_strerror(err, strerr, 256);
        printf("err = %s\n", strerr);
        return;
    }
    init_sessions();
    // === Bind to dynamic port ===
    tls_sockfd = bind_v2gport(&tls_port);
    if (tls_sockfd < 0) {
        printf("secc_bind_tls  returned %d\n", tls_sockfd);
        return;
    }
    tcp_sockfd = bind_v2gport(&tcp_port);
    if (tcp_sockfd < 0) {
        printf("secc_bind_tls  returned %d\n", tcp_sockfd);
        return;
    }
    printf("start sdp listen\n");
    secc_listen_tls(tls_sockfd, &create_response_message, "certs/evse.pem", "certs/evse.key");
    secc_listen_tcp(tcp_sockfd, &create_response_message);
    // Set port to 0 to disable tls or tcp
    // (always do sdp_listen after secc_listen_*)
    sdp_listen(if_name, tls_port, tcp_port);
}

void usage(void)
{
    fprintf(stderr, "Usage: %s [-sv] [--] interface node-type\n", argv0);
    exit(1);
}

void
threadmain(int argc,
       char *argv[])
{
    enum { EV, EVSE };
    const char *iface, *type;
    int opt, slac = 0, notls = 0;
	char *can_intf_name; // Added by JJS (2019.02.19)

    argv0 = argv[0];
    while ((opt = getopt(argc, argv, "svnft")) != -1) {
        switch (opt) {
        case 's': // Enable SLAC
           slac++;
           break;

        case 'v': // Verbose
            chattyv2g++;
            chattyslac++;
            break;
        case 'n': // no tls
            notls++;
            break;
        case 'f':
            secc_free_charge++;
            break;
        case 't':
            enable_timeprofiling++;
            break;
        default:
            usage();
        }
    }
    if (optind + 1 >= argc) { usage(); }

    iface = argv[optind];
    type = argv[optind + 1];
	can_intf_name = argv[optind + 2]; // Added by JJS (2019.02.19)
    if (strcasecmp(type, "EVSE") == 0) {
        switch_power_line(iface, EVSEMAC, false);
        if (slac) {
            printf("SLAC enabled\n");
            plgp_slac_listen(iface, EVSEMAC);
        }
        evse(iface, can_intf_name); // modifed by JJS (2019.02.19)
    } else if (strcasecmp(type, "EV") == 0) {
        if (slac) {
            switch_power_line(iface, EVMAC, false);
            printf("=== STARTING SLAC ASSOCIATION ===\n");
            while(slac_associate(iface) != 0) {
                printf("something went wrong, trying again\n");
            }
            printf("Slac is done. Waiting 8 seconds for networks to form.\n");
            sleep(8);
        }
       ev(iface, !notls, can_intf_name); // modifed by JJS (2019.02.19)
    } else {
        fatal("node type must be EV or EVSE");
     }
    printf("Exiting\n");
    exit(0);
}
