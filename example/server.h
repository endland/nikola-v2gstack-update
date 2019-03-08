#ifndef SERVER_H
#define SERVER_H
extern int secc_free_charge;
#include <OpenV2G_0.9.4/iso1EXIDatatypes.h> // Modified by JJS (2019.02.07)
#include <mbedtls/x509.h>

typedef struct session_data session_data_t;
struct session_data {
    uint8_t evcc_id[6]; // EV mac address
    struct iso1SelectedServiceType services[iso1SelectedServiceListType_SelectedService_ARRAY_SIZE]; // Modified by JJS (2019.02.07)
    iso1EnergyTransferModeType energy_transfer_mode; // Modified by JJS (2019.02.07)
    iso1paymentOptionType payment_type; // Modified by JJS (2019.02.07)
    struct iso1SAScheduleListType SAScheduleList; // Modified by JJS (2019.02.07)
    bool SAScheduleList_isUsed;
    uint8_t challenge[16];
    bool verified;
    bool charging;
    bool tls_enabled;
    bool renegotiation_required;
    struct{
        bool valid_crt; // Before a contract can be valid, it must have a valid crt
        //byte cert[v2gCertificateChainType_Certificate_BYTES_SIZE];
        //size_t cert_len;
        mbedtls_x509_crt crt;
        mbedtls_ecdsa_context pubkey;
    } contract;
};
void session_data_cleanup(session_t *s);
void init_v2g_response(struct iso1EXIDocument *exiOut, session_t *s); // Modified by JJS (2019.02.07)
int verify_charging_profile(session_data_t *sd, uint8_t tupleid, struct iso1ChargingProfileType *profile); // Modified by JJS (2019.02.07)

extern mbedtls_x509_crt Trusted_contract_rootcert_chain;

int create_response_message(struct iso1EXIDocument *exiIn, struct iso1EXIDocument *exiOut, bool tls_enabled); // Modified by JJS (2019.02.07)


int handle_session_setup(struct iso1EXIDocument *exiIn, // Modified by JJS (2019.02.07)
                         struct iso1EXIDocument *exiOut, // Modified by JJS (2019.02.07)
                         session_t *s, session_data_t *sd);
int handle_service_discovery(struct iso1EXIDocument *exiIn, // Modified by JJS (2019.02.07)
                             struct iso1EXIDocument *exiOut, // Modified by JJS (2019.02.07)
                             session_t *s, session_data_t *sd);
int payment_service_selection(struct iso1EXIDocument *exiIn, // Modified by JJS (2019.02.07)
                              struct iso1EXIDocument *exiOut, // Modified by JJS (2019.02.07)
                              session_t *s, session_data_t *sd);
int handle_service_detail(struct iso1EXIDocument *exiIn, // Modified by JJS (2019.02.07)
                          struct iso1EXIDocument *exiOut, // Modified by JJS (2019.02.07)
                          session_t *s, session_data_t *sd);
int handle_payment_detail(struct iso1EXIDocument *exiIn, // Modified by JJS (2019.02.07)
                          struct iso1EXIDocument *exiOut, // Modified by JJS (2019.02.07)
                          session_t *s, session_data_t *sd);
int handle_authorization(struct iso1EXIDocument *exiIn, // Modified by JJS (2019.02.07)
                         struct iso1EXIDocument *exiOut, // Modified by JJS (2019.02.07)
                         session_t *s, session_data_t *sd);
int handle_charge_parameters(struct iso1EXIDocument *exiIn, // Modified by JJS (2019.02.07)
                             struct iso1EXIDocument *exiOut, // Modified by JJS (2019.02.07)
                             session_t *s, session_data_t *sd);
int handle_power_delivery(struct iso1EXIDocument *exiIn, // Modified by JJS (2019.02.07)
                          struct iso1EXIDocument *exiOut, // Modified by JJS (2019.02.07)
                          session_t *s, session_data_t *sd);
int handle_charging_status(struct iso1EXIDocument *exiIn, // Modified by JJS (2019.02.07)
                           struct iso1EXIDocument *exiOut, // Modified by JJS (2019.02.07)
                           session_t *s, session_data_t *sd);
int handle_session_stop(struct iso1EXIDocument *exiIn, // Modified by JJS (2019.02.07)
                        struct iso1EXIDocument *exiOut, // Modified by JJS (2019.02.07)
                        session_t *s, session_data_t *sd);

#endif
