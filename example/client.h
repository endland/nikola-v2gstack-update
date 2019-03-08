#ifndef EXAMPLE_CLIENT_H
#define EXAMPLE_CLIENT_H
typedef struct ev_session ev_session_t;
struct ev_session{
    uint64_t id;
    uint16_t charge_service_id;
    bool charging_is_free;
    iso1EVSENotificationType evse_notification; // Modified by JJS (2019.02.07)
    uint8_t challenge[16];
    struct{
        bool is_used;
        uint8_t tupleid;
    } pmax_schedule;
    struct{
        uint8_t cert[iso1CertificateChainType_Certificate_BYTES_SIZE]; // Modified by JJS (2019.02.07)
        size_t cert_len;
        uint8_t  sub_certs[iso1SubCertificatesType_Certificate_ARRAY_SIZE][iso1CertificateChainType_Certificate_BYTES_SIZE]; // Modified by JJS (2019.02.07)
        size_t subcert_len[iso1SubCertificatesType_Certificate_ARRAY_SIZE]; // Modified by JJS (2019.02.07)
        mbedtls_ecdsa_context key;
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
    } contract;
};
void init_v2g_request(struct iso1EXIDocument *exiIn, ev_session_t *s); // Modified by JJS (2019.02.07)
void SetProfileEntry(struct iso1ChargingProfileType* prof, // Modified by JJS (2019.02.07)
                     uint32_t start, int32_t value,
                     uint32_t nphases);
int verify_response_code(iso1responseCodeType code); // Modified by JJS (2019.02.07)
void evcc_session_cleanup(ev_session_t* s);
int load_contract(const char *pemchain_path, const char *keyfile_path, ev_session_t *s);
int sign_auth_request(struct iso1AuthorizationReqType *req, // Modified by JJS (2019.02.07)
                      mbedtls_ecdsa_context *key,
                      mbedtls_ctr_drbg_context *ctr_drbg,
                      struct iso1SignatureType *sig); // Modified by JJS (2019.02.07)
int session_request(evcc_conn_t *conn, ev_session_t *s);
int service_discovery_request(evcc_conn_t *conn, ev_session_t *s);
int payment_selection_request(evcc_conn_t *conn, ev_session_t *s);
int payment_details_request(evcc_conn_t *conn, ev_session_t *s);
int authorization_request(evcc_conn_t *conn, ev_session_t *s);
int charge_parameter_request(evcc_conn_t *conn, ev_session_t *s);
int power_delivery_request(evcc_conn_t *conn, ev_session_t *s, iso1chargeProgressType progress); // Modified by JJS (2019.02.07)
int charging_status_request(evcc_conn_t *conn, ev_session_t *s);
int session_stop_request(evcc_conn_t *conn, ev_session_t *s);

#endif
