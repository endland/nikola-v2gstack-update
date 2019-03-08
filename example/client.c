#include <stdio.h>
#include <nikolav2g_0.9.4.h>
#include <OpenV2G_0.9.4/EXITypes.h>
#include <OpenV2G_0.9.4/iso1EXIDatatypes.h> // Modified by JJS (2019.02.07)
#include <OpenV2G_0.9.4/iso1EXIDatatypesEncoder.h> // Modified by JJS (2019.02.07)
#include <OpenV2G_0.9.4/xmldsigEXIDatatypes.h>
#include <OpenV2G_0.9.4/xmldsigEXIDatatypesEncoder.h>
#include <OpenV2G_0.9.4/v2gtp.h>
#include <string.h>
#include <unistd.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecdsa.h>
#include <fcntl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include "client.h"
#include <mbedtls/sha256.h> // Added by JJS (2019.02.02)


//=========================================
//            Utility Functions
//=========================================

void evcc_session_cleanup(ev_session_t* s) {
    mbedtls_ctr_drbg_free(&s->contract.ctr_drbg);
    mbedtls_ecdsa_free(&s->contract.key);
    mbedtls_entropy_free(&s->contract.entropy);
}

int load_contract(const char *pemchain_path,
                  const char *keyfile_path,
                  ev_session_t *s) {
    int err, i = 0;
    mbedtls_x509_crt crtchain;
    mbedtls_x509_crt* crt;
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);
    const char *pers = "ecdsa";
    mbedtls_x509_crt_init(&crtchain);
    err = mbedtls_x509_crt_parse_file(&crtchain, pemchain_path);
    if (err != 0) {
        printf("load_contract: x509_crl_parse_file error\n");
        return -1;
    }
    if (crtchain.raw.len > iso1CertificateChainType_Certificate_BYTES_SIZE) { // Modified by JJS (2019.02.07)
        printf("load_contract: certificate too big\n");
        return -1;
    }
    memcpy(&s->contract.cert, crtchain.raw.p, crtchain.raw.len);
    s->contract.cert_len = crtchain.raw.len;
    crt = &crtchain;
    while (crt->next != NULL) {
        if (i > iso1SubCertificatesType_Certificate_ARRAY_SIZE) { // Modified by JJS (2019.02.07)
            printf("load_contract: certificate chain too long (max 4 subcerts)\n");
            return -1;
        }
        crt = crt->next;
        if (crt->raw.len > iso1SubCertificatesType_Certificate_BYTES_SIZE) { // Modified by JJS (2019.02.07)
            printf("load_contract: subcertificate too big\n");
            return -1;
        }
        memcpy(&s->contract.sub_certs[i], crt->raw.p, crt->raw.len);
        s->contract.subcert_len[i] = crt->raw.len;
        i++;
    }
    mbedtls_x509_crt_free(&crtchain);
    err = mbedtls_pk_parse_keyfile(&pk, keyfile_path, NULL);
    if (err != 0) {
        printf("could not parse keyfile at %s\n",keyfile_path);
        return -1;
    }
    mbedtls_ecp_keypair *kp = mbedtls_pk_ec(pk);
    mbedtls_ecdsa_free(&s->contract.key); // Free, if existing already
    err = mbedtls_ecdsa_from_keypair(&s->contract.key, kp);
    mbedtls_pk_free(&pk);
    if (err != 0) {
        printf("could not retrieve ecdsa from keypair at %s\n",keyfile_path);
        return -1;
    }

    mbedtls_entropy_init(&s->contract.entropy);
    /*if ((err = mbedtls_ctr_drbg_init(&s->contract.ctr_drbg, mbedtls_entropy_func,
                             &s->contract.entropy,
                             (const unsigned char*)pers,
                             strlen(pers))) != 0) {
        printf("load_contract:  failed\n  ! ctr_drbg_init returned %d\n", err);
        return -1;
    }*/ // Removed by JJS (2019.02.02)
    mbedtls_ctr_drbg_init(&s->contract.ctr_drbg); // Added by JJS (2019.02.02)
	if ((err = mbedtls_ctr_drbg_seed(&s->contract.ctr_drbg, mbedtls_entropy_func,
                             &s->contract.entropy,
                             (const unsigned char*)pers,
                             strlen(pers))) != 0) {
        printf("load_contract:  failed\n  ! ctr_drbg_init returned %d\n", err);
        return -1;
    } // Added by JJS (2019.02.02)
    return 0;
}

int sign_auth_request(struct iso1AuthorizationReqType *req, // Modified by JJS (2019.02.07)
                      mbedtls_ecdsa_context *key,
                      mbedtls_ctr_drbg_context *ctr_drbg,
                      struct iso1SignatureType *sig) { // Modified by JJS (2019.02.07)
    int err;
    unsigned char buf[256];
    uint8_t digest[32];
    size_t buffer_pos = 0; // Modified by JJS (2019.02.07)
    bitstream_t stream = {
        .size = 256,
        .data = buf,
        .pos  = &buffer_pos,
        .buffer = 0,
        .capacity = 8, // Set to 8 for send and 0 for recv
    };
   //struct v2gEXIDocument exiIn;
    struct iso1EXIFragment auth_fragment; // Modified by JJS (2019.02.07)
    init_iso1EXIFragment(&auth_fragment); // Modified by JJS (2019.02.07)
    auth_fragment.AuthorizationReq_isUsed = 1u;
    memcpy(&auth_fragment.AuthorizationReq, req, sizeof(struct iso1AuthorizationReqType)); // Modified by JJS (2019.02.07)
    err = encode_iso1ExiFragment(&stream, &auth_fragment); // Modified by JJS (2019.02.07)
    if (err != 0) {
        printf("error 1: error code = %d\n", err);
        return -1;
    }
    mbedtls_sha256(buf, (size_t)buffer_pos, digest, 0);
    //=======================================
    //      Create signature
    //=======================================
    struct xmldsigEXIFragment sig_fragment;
    memset(&sig_fragment, 0, sizeof(sig_fragment));
    struct xmldsigReferenceType *ref = &sig_fragment.SignedInfo.Reference.array[0];
    char uri[4] = {"#ID1"};
	char arrayCanonicalEXI[35] = {"http://www.w3.org/TR/canonical-exi/"};
	char arrayxmldsigSHA256[51] = {"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"};
	char arrayxmlencSHA256[39] = {"http://www.w3.org/2001/04/xmlenc#sha256"};
	init_xmldsigEXIFragment(&sig_fragment);
	sig_fragment.SignedInfo_isUsed = 1;
	init_xmldsigSignedInfoType(&sig_fragment.SignedInfo);
	init_xmldsigCanonicalizationMethodType(&sig_fragment.SignedInfo.CanonicalizationMethod);
	sig_fragment.SignedInfo.CanonicalizationMethod.Algorithm.charactersLen = 35;
	memcpy(sig_fragment.SignedInfo.CanonicalizationMethod.Algorithm.characters, arrayCanonicalEXI, 35);
	sig_fragment.SignedInfo.SignatureMethod.HMACOutputLength_isUsed = 0;
	sig_fragment.SignedInfo.SignatureMethod.Algorithm.charactersLen = 51;
	strncpy(sig_fragment.SignedInfo.SignatureMethod.Algorithm.characters, arrayxmldsigSHA256, 51);
	sig_fragment.SignedInfo.Reference.arrayLen = 1;
	ref->URI_isUsed = 1;
	ref->URI.charactersLen = 4;
	memcpy(ref->URI.characters, uri, 4);
	// "http://www.w3.org/TR/canonical-exi/"
	ref->Transforms_isUsed = 1;
	ref->Transforms.Transform.arrayLen = 1;
	ref->Transforms.Transform.array[0].Algorithm.charactersLen = 35;
	strncpy(ref->Transforms.Transform.array[0].Algorithm.characters, arrayCanonicalEXI, 35); // Will copy 35 characters from arrayCanonicalEXI to characters
	ref->Transforms.Transform.array[0].XPath.arrayLen = 0;
	ref->DigestMethod.Algorithm.charactersLen = 39;
	strncpy(ref->DigestMethod.Algorithm.characters, arrayxmlencSHA256, 39);
	ref->DigestValue.bytesLen = 32;
	memcpy(ref->DigestValue.bytes, digest, 32);
    buffer_pos = 0;
	err = encode_xmldsigExiFragment(&stream, &sig_fragment);
    if (err != 0) {
        printf("error 2: error code = %d\n", err);
        return -1;
    }
    memcpy(&sig->SignedInfo, &sig_fragment.SignedInfo, sizeof(struct iso1SignedInfoType)); // Modified by JJS (2019.02.07)
    mbedtls_sha256(buf, (size_t)buffer_pos, digest, 0); // Modified by JJS (2019.02.13)
    err = mbedtls_ecdsa_write_signature(key, MBEDTLS_MD_SHA256,
                                digest, 32,
                                sig->SignatureValue.CONTENT.bytes,
                                (size_t*)&sig->SignatureValue.CONTENT.bytesLen,
                                mbedtls_ctr_drbg_random,
                                ctr_drbg); // Modified by JJS (2019.02.02)
    if (err != 0) {
        printf("ecdsa write sig err\n");
        return -1;
    }
    //sig->KeyInfo_isUsed = 0; // Removed by JJS (2019.02.09)
	//sig->Id_isUsed = 0; // Removed by JJS (2019.02.09)
	//sig->Object.arrayLen = 1; // Removed by JJS (2019.02.09)
	//sig->Object.array[0].Id_isUsed = 0; // Removed by JJS (2019.02.09)
	//sig->Object.array[0].MimeType_isUsed = 0; // Removed by JJS (2019.02.09)
	//sig->Object.array[0].Encoding_isUsed = 0; // Removed by JJS (2019.02.09)
	//sig->SignatureValue.Id_isUsed = 0; // Removed by JJS (2019.02.09)
    return 0;
}

void SetProfileEntry(struct iso1ChargingProfileType* prof, // Modified by JJS (2019.02.07)
                     uint32_t start, int32_t value,
                     uint32_t nphases)
{
    uint16_t* counter = &prof->ProfileEntry.arrayLen;
    const int max_value = (2 << 16) - 1;
    const int max_power = (2 << 8) - 1;
    int power = 0;
    while(abs(value) > max_value &&
          power < max_power) {
        value /= 10;
        power ++;
    }

    prof->ProfileEntry.array[*counter] =  (struct iso1ProfileEntryType) { // Modified by JJS (2019.02.07)
        .ChargingProfileEntryStart = start,
        .ChargingProfileEntryMaxNumberOfPhasesInUse = nphases,
        .ChargingProfileEntryMaxNumberOfPhasesInUse_isUsed = 1u,
        .ChargingProfileEntryMaxPower = (struct iso1PhysicalValueType) { // Modified by JJS (2019.02.07)
	        .Value = value,
	        .Multiplier = power,
	        .Unit = iso1unitSymbolType_W, // Modified by JJS (2019.02.07)
	    },
	};
    (*counter)++;
}


/*static void printACEVSEStatus(struct v2gAC_EVSEStatusType *status)
{
	printf("\tEVSEStatus:\n");
	printf("\t\tRCD=%d\n", status->RCD);
	printf("\t\tEVSENotification=%d\n", status->EVSENotification);
	printf("\t\tNotificationMaxDelay=%d\n", status->NotificationMaxDelay);
}*/

int verify_response_code(iso1responseCodeType code)
{
    switch (code) {
    case iso1responseCodeType_OK:
        return 0;
	case iso1responseCodeType_OK_NewSessionEstablished:
	    return 0;
	case iso1responseCodeType_OK_OldSessionJoined:
	    return 0;
	case iso1responseCodeType_OK_CertificateExpiresSoon:
	    return 0;
    case iso1responseCodeType_FAILED:
	case iso1responseCodeType_FAILED_SequenceError:
	case iso1responseCodeType_FAILED_ServiceIDInvalid:
	case iso1responseCodeType_FAILED_UnknownSession:
	case iso1responseCodeType_FAILED_ServiceSelectionInvalid:
	case iso1responseCodeType_FAILED_PaymentSelectionInvalid:
	case iso1responseCodeType_FAILED_CertificateExpired:
	case iso1responseCodeType_FAILED_SignatureError:
	case iso1responseCodeType_FAILED_NoCertificateAvailable:
	case iso1responseCodeType_FAILED_CertChainError:
	case iso1responseCodeType_FAILED_ChallengeInvalid:
	case iso1responseCodeType_FAILED_ContractCanceled:
	case iso1responseCodeType_FAILED_WrongChargeParameter:
	case iso1responseCodeType_FAILED_PowerDeliveryNotApplied:
	case iso1responseCodeType_FAILED_TariffSelectionInvalid:
	case iso1responseCodeType_FAILED_ChargingProfileInvalid:
	case iso1responseCodeType_FAILED_MeteringSignatureNotValid:
	case iso1responseCodeType_FAILED_NoChargeServiceSelected:
	case iso1responseCodeType_FAILED_WrongEnergyTransferMode:
	case iso1responseCodeType_FAILED_ContactorError:
	//case v2gresponseCodeType__FAILED_CertificateNotAllowedAtThisEVSE:
	case iso1responseCodeType_FAILED_CertificateRevoked:
	default:
	    return -1;
    }
} // Modified by JJS (2019.02.07)


void init_v2g_request(struct iso1EXIDocument *exiIn, ev_session_t *s) // Modified by JJS (2019.02.07)
{
    memset(exiIn, 0, sizeof(*exiIn));
    init_iso1EXIDocument(exiIn); // Modified by JJS (2019.02.07)
	exiIn->V2G_Message_isUsed = 1u;
	init_iso1MessageHeaderType(&exiIn->V2G_Message.Header); // Modified by JJS (2019.02.07)
	// Set session id to 0
	if (s == NULL) {
	    memset(exiIn->V2G_Message.Header.SessionID.bytes, 0, 8);
	} else {
	    memcpy(exiIn->V2G_Message.Header.SessionID.bytes, &s->id, 8);
	}
	exiIn->V2G_Message.Header.SessionID.bytesLen = 8;
	exiIn->V2G_Message.Header.Notification_isUsed = 0u; // no notification
	exiIn->V2G_Message.Header.Signature_isUsed = 0u;
    init_iso1BodyType(&exiIn->V2G_Message.Body); // Modified by JJS (2019.02.07)
}

//=======================
//  Request Definitions
//=======================
int session_request(evcc_conn_t *conn, ev_session_t *s)
{
    int err;
    struct iso1EXIDocument exiIn; // Modified by JJS (2019.02.07)
    struct iso1EXIDocument exiOut; // Modified by JJS (2019.02.07)
    init_v2g_request(&exiIn, NULL);
	exiIn.V2G_Message.Body.SessionSetupReq_isUsed = 1u;

	init_iso1SessionSetupReqType(&exiIn.V2G_Message.Body.SessionSetupReq); // Modified by JJS (2019.02.07)

	exiIn.V2G_Message.Body.SessionSetupReq.EVCCID.bytesLen = 1;
	exiIn.V2G_Message.Body.SessionSetupReq.EVCCID.bytes[0] = 20;
	err = v2g_request(conn, &exiIn, &exiOut);
    if (err != 0) {
        printf("unable to do v2g_request, exiting\n");
        return -1;
    }
    // === Validate response type ===
    if (exiOut.V2G_Message.Body.SessionSetupRes_isUsed != 1u) {
        printf("session_request: wrong response type\n");
        return -1;
    }
    // === Validate response code ===
    if (verify_response_code(exiOut.V2G_Message.Body.SessionSetupRes.ResponseCode) != 0) {
        printf("session_request: session setup response NOT ok, code = %d\n", exiOut.V2G_Message.Body.SessionSetupRes.ResponseCode);
        return -1;
    }
    // === Save session id ===
    memcpy(&s->id, exiOut.V2G_Message.Header.SessionID.bytes, 8);

    return 0;
}

int service_discovery_request(evcc_conn_t *conn, ev_session_t *s)
{
    int err;
    struct iso1EXIDocument exiIn; // Modified by JJS (2019.02.07)
    struct iso1EXIDocument exiOut; // Modified by JJS (2019.02.07)
    // === Init ===
    init_v2g_request(&exiIn, s);
	exiIn.V2G_Message.Body.ServiceDiscoveryReq_isUsed = 1u;
	init_iso1ServiceDiscoveryReqType(&exiIn.V2G_Message.Body.ServiceDiscoveryReq); // Modified by JJS (2019.02.07)

    exiIn.V2G_Message.Body.ServiceDiscoveryReq.ServiceCategory_isUsed = 1u;
	exiIn.V2G_Message.Body.ServiceDiscoveryReq.ServiceCategory = iso1serviceCategoryType_EVCharging; // Modified by JJS (2019.02.07)
	exiIn.V2G_Message.Body.ServiceDiscoveryReq.ServiceScope_isUsed = 0u;
	err = v2g_request(conn, &exiIn, &exiOut);
    if (err != 0) {
        printf("unable to do v2g_request, exiting\n");
        return -1;
    }
    // === Validate response type ===
    if (exiOut.V2G_Message.Body.ServiceDiscoveryRes_isUsed != 1u) {
        printf("service_discovery_request: wrong response type\n");
        return -1;
    }
    // === Validate response code ===
    if (verify_response_code(exiOut.V2G_Message.Body.ServiceDiscoveryRes.ResponseCode) != 0) {
        printf("service_discovery_request: response NOT ok, code = %d\n", exiOut.V2G_Message.Body.ServiceDiscoveryRes.ResponseCode);
        return -1;
    }
    s->charge_service_id = exiOut.V2G_Message.Body.ServiceDiscoveryRes.ChargeService.ServiceID;
    s->charging_is_free = exiOut.V2G_Message.Body.ServiceDiscoveryRes.ChargeService.FreeService && 1;
    return 0;
}

int payment_selection_request(evcc_conn_t *conn, ev_session_t *s)
{
    int err;
    struct iso1EXIDocument exiIn; // Modified by JJS (2019.02.07)
    struct iso1EXIDocument exiOut; // Modified by JJS (2019.02.07)
    init_v2g_request(&exiIn, s);
	init_iso1PaymentServiceSelectionReqType(&exiIn.V2G_Message.Body.PaymentServiceSelectionReq); // Modified by JJS (2019.02.07)
    exiIn.V2G_Message.Body.PaymentServiceSelectionReq_isUsed = 1u;

    if (!s->charging_is_free) {
	    exiIn.V2G_Message.Body.PaymentServiceSelectionReq.SelectedPaymentOption = iso1paymentOptionType_Contract; // Modified by JJS (2019.02.07)
	}	
	exiIn.V2G_Message.Body.PaymentServiceSelectionReq.SelectedServiceList.SelectedService.arrayLen = 1; // === only one service was selected ===
	exiIn.V2G_Message.Body.PaymentServiceSelectionReq.SelectedServiceList.SelectedService.array[0].ServiceID = s->charge_service_id; // charge server ID
	exiIn.V2G_Message.Body.PaymentServiceSelectionReq.SelectedServiceList.SelectedService.array[0].ParameterSetID_isUsed = 0u; // is not used


	err = v2g_request(conn, &exiIn, &exiOut);
    if (err != 0) {
        printf("unable to do payment_selection_request v2g_request, exiting\n");
        return -1;
    }
    // === Validate response type ===
    if (exiOut.V2G_Message.Body.PaymentServiceSelectionRes_isUsed != 1u) {
        printf("payment_selection_request: wrong response type\n");
        return -1;
    }
    // === Validate response code ===
    if (verify_response_code(exiOut.V2G_Message.Body.PaymentServiceSelectionRes.ResponseCode) != 0) {
        printf("payment_selection_request: response NOT ok, code = %d\n", exiOut.V2G_Message.Body.PaymentServiceSelectionRes.ResponseCode);
        return -1;
    }
    return 0;
}

int payment_details_request(evcc_conn_t *conn, ev_session_t *s)
{
    int err;
    struct iso1EXIDocument exiIn; // Modified by JJS (2019.02.07)
    struct iso1EXIDocument exiOut; // Modified by JJS (2019.02.07)
    struct iso1PaymentDetailsReqType *req = &exiIn.V2G_Message.Body.PaymentDetailsReq; // Modified by JJS (2019.02.07)
    struct iso1PaymentDetailsResType *res = &exiOut.V2G_Message.Body.PaymentDetailsRes; // Modified by JJS (2019.02.07)
    init_v2g_request(&exiIn, s);
	init_iso1PaymentDetailsReqType(req); // Modified by JJS (2019.02.07)
    exiIn.V2G_Message.Body.PaymentDetailsReq_isUsed = 1u;
	req->eMAID.characters[0] = 'I'; // Modified by JJS (2019.02.09)
	req->eMAID.characters[1] = 'D'; // Modified by JJS (2019.02.09)
	req->eMAID.characters[2] = '1'; // Added by JJS (2019.02.09)
	req->eMAID.charactersLen = 3; // Modified by JJS (2019.02.09)
	if (s->contract.cert_len == 0) {
	    printf("payment_details_request: contract certificate not loaded\n");
	    return -1;
	}
    memcpy(req->ContractSignatureCertChain.Certificate.bytes, s->contract.cert, s->contract.cert_len);
	req->ContractSignatureCertChain.Certificate.bytesLen = s->contract.cert_len;
	req->ContractSignatureCertChain.SubCertificates_isUsed = 1u;
	memcpy(req->ContractSignatureCertChain.SubCertificates.Certificate.array[0].bytes, s->contract.sub_certs[0], s->contract.subcert_len[0]);
    req->ContractSignatureCertChain.SubCertificates.Certificate.array[0].bytesLen = s->contract.subcert_len[0];
	memcpy(req->ContractSignatureCertChain.SubCertificates.Certificate.array[1].bytes, s->contract.sub_certs[1], s->contract.subcert_len[1]); // Added by JJS (2019.02.09)
    req->ContractSignatureCertChain.SubCertificates.Certificate.array[1].bytesLen = s->contract.subcert_len[1]; // Added by JJS (2019.02.09)
    req->ContractSignatureCertChain.SubCertificates.Certificate.arrayLen = 2;
    req->ContractSignatureCertChain.Id_isUsed = 0;
	err = v2g_request(conn, &exiIn, &exiOut);
    if (err != 0) {
        printf("unable to do payment_details_request v2g_request, exiting\n");
        return -1;
    }
    // === Validate response type ===
    if (exiOut.V2G_Message.Body.PaymentDetailsRes_isUsed != 1u) {
        printf("payment_details_request: wrong response type\n");
        return -1;
    }
    // === Validate response code ===
    if (verify_response_code(res->ResponseCode) != 0) {
        printf("payment_details_request: session setup response NOT ok, code = %d\n", res->ResponseCode);
        return -1;
    }
    if (res->GenChallenge.bytesLen != 16) {
        printf("payment_details: Invalid genchallenge length %u, length must me 16\n", res->GenChallenge.bytesLen);
        return -1;
    }
    memcpy(s->challenge, res->GenChallenge.bytes, 16);
    return 0;
}

int authorization_request(evcc_conn_t *conn, ev_session_t *s)
{
    int err;
    struct iso1EXIDocument exiIn; // Modified by JJS (2019.02.07)
    struct iso1EXIDocument exiOut; // Modified by JJS (2019.02.07)
    struct iso1AuthorizationReqType *req = &exiIn.V2G_Message.Body.AuthorizationReq; // Modified by JJS (2019.02.07)
    struct iso1AuthorizationResType *res = &exiOut.V2G_Message.Body.AuthorizationRes; // Modified by JJS (2019.02.07)
    init_v2g_request(&exiIn, s);
	init_iso1AuthorizationReqType(req); // Modified by JJS (2019.02.07)
	exiIn.V2G_Message.Body.AuthorizationReq_isUsed = 1u;
	req->Id_isUsed = 1u;
    req->Id.characters[0] = 'I';
    req->Id.characters[1] = 'D';
    req->Id.characters[2] = '1';
    req->Id.charactersLen = 3;
    if (!s->charging_is_free) {
	    req->GenChallenge_isUsed = 1;
        memcpy(req->GenChallenge.bytes, s->challenge, 16);
	    req->GenChallenge.bytesLen = 16;

	    exiIn.V2G_Message.Header.Signature_isUsed = 1u;
	    sign_auth_request(req, &s->contract.key,
	                       &s->contract.ctr_drbg,
	                       &exiIn.V2G_Message.Header.Signature);
	}

	err = v2g_request(conn, &exiIn, &exiOut);
    if (err != 0) {
        printf("unable to do authorization v2g_request, exiting\n");
        return -1;
    }
    // === Validate response type ===
    if (exiOut.V2G_Message.Body.AuthorizationRes_isUsed != 1u) {
        printf("authorization_request: wrong response type\n");
        return -1;
    }
    // === Validate response code ===
    /*if (verify_response_code(res->ResponseCode) != 0) {
        printf("authorization_request: authorization response NOT ok, code = %d\n", res->ResponseCode);
        return -1;
    }*/ // Modified by JJS (2019.02.08) // Modified by JJS (2019.02.10)
	if (res->EVSEProcessing != iso1EVSEProcessingType_Finished) { // Modified by JJS (2019.02.07)
        printf("\t EVSEProcessing=Not Finished\n");
        return -1;
	}
    return 0;
}

int charge_parameter_request(evcc_conn_t *conn, ev_session_t *s)
{
    int err;
    struct iso1EXIDocument exiIn; // Modified by JJS (2019.02.07)
    struct iso1EXIDocument exiOut; // Modified by JJS (2019.02.07)
    struct iso1ChargeParameterDiscoveryReqType *req = &exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq; // Modified by JJS (2019.02.07)
    struct iso1ChargeParameterDiscoveryResType *res = &exiOut.V2G_Message.Body.ChargeParameterDiscoveryRes; // Modified by JJS (2019.02.07)
    struct iso1AC_EVChargeParameterType *charge_params = &req->AC_EVChargeParameter; // Modified by JJS (2019.02.07)
    init_v2g_request(&exiIn, s);
    exiIn.V2G_Message.Body.ChargeParameterDiscoveryReq_isUsed = 1u;
	init_iso1ChargeParameterDiscoveryReqType(req); // Modified by JJS (2019.02.07)

	//=== we use here AC based charging parameters ===
	req->RequestedEnergyTransferMode = iso1EnergyTransferModeType_AC_single_phase_core; // Modified by JJS (2019.02.07)
	req->MaxEntriesSAScheduleTuple = 1234;

	req->AC_EVChargeParameter_isUsed = 1u;

	*charge_params = (struct iso1AC_EVChargeParameterType) { // Modified by JJS (2019.02.07)
	    .DepartureTime = 0,
	    .EAmount = (struct iso1PhysicalValueType) { // Modified by JJS (2019.02.07)
	        .Value = 5,
	        .Multiplier = 3,
	        .Unit = iso1unitSymbolType_Wh, // Modified by JJS (2019.02.07)
	    },
	    .EVMaxCurrent = (struct iso1PhysicalValueType) { // Modified by JJS (2019.02.07)
	        .Value = 32,
	        .Multiplier = 0,
	        .Unit = iso1unitSymbolType_A, // Modified by JJS (2019.02.07)
	    },
	    .EVMinCurrent = (struct iso1PhysicalValueType) { // Modified by JJS (2019.02.07)
	        .Value = 5,
	        .Multiplier = 0,
	        .Unit = iso1unitSymbolType_A, // Modified by JJS (2019.02.07)
	    },
	    .EVMaxVoltage = (struct iso1PhysicalValueType) { // Modified by JJS (2019.02.07)
	        .Value = 400,
	        .Multiplier = 0,
	        .Unit = iso1unitSymbolType_V, // Modified by JJS (2019.02.07)
	    },
	};

	err = v2g_request(conn, &exiIn, &exiOut);
    if (err != 0) {
        printf("unable to do charge_parameter v2g_request, exiting\n");
        return -1;
    }
    // === Validate response type ===
    if (exiOut.V2G_Message.Body.ChargeParameterDiscoveryRes_isUsed != 1u) {
        printf("charge_parameter_request: wrong response type\n");
        return -1;
    }
    // === Validate response code ===
    if (verify_response_code(res->ResponseCode) != 0) {
        printf("charge_parameter_request: authorization response NOT ok, code = %d\n", res->ResponseCode);
        return -1;
    }
    // === Decide which tuple to use ===
    if (res->SAScheduleList_isUsed && res->SAScheduleList.SAScheduleTuple.arrayLen > 0) {
        // === One can implement advanced logic to decide which tuple should be used here ===
        s->pmax_schedule.is_used = true;
        s->pmax_schedule.tupleid = res->SAScheduleList.SAScheduleTuple.array[0].SAScheduleTupleID;
    }
    // === Print digest ===
	/*printACEVSEStatus(&(res->AC_EVSEChargeParameter.AC_EVSEStatus));
	printf("\t EVSEProcessing=%d\n", res->EVSEProcessing);
	printf("\t EVSEMaxCurrent=%d\n", res->AC_EVSEChargeParameter.EVSEMaxCurrent.Value);
	printf("\t EVSENominalVoltage=%d\n", res->AC_EVSEChargeParameter.EVSENominalVoltage.Value);*/
    return 0;
}

int power_delivery_request(evcc_conn_t *conn, ev_session_t *s,
                            iso1chargeProgressType progress) // Modified by JJS (2019.02.07)
{
    int err;
    struct iso1EXIDocument exiIn; // Modified by JJS (2019.02.07)
    struct iso1EXIDocument exiOut; // Modified by JJS (2019.02.07)
    struct iso1ChargingProfileType *profile = &exiIn.V2G_Message.Body.PowerDeliveryReq.ChargingProfile; // Modified by JJS (2019.02.07)

    init_v2g_request(&exiIn, s);
    exiIn.V2G_Message.Body.PowerDeliveryReq_isUsed = 1u;
	init_iso1PowerDeliveryReqType(&exiIn.V2G_Message.Body.PowerDeliveryReq); // Modified by JJS (2019.02.07)

	exiIn.V2G_Message.Body.PowerDeliveryReq.DC_EVPowerDeliveryParameter_isUsed = 0;
	exiIn.V2G_Message.Body.PowerDeliveryReq.ChargeProgress = progress;

	// === A charging profile is used for this request===

	exiIn.V2G_Message.Body.PowerDeliveryReq.SAScheduleTupleID  = s->pmax_schedule.tupleid;

    if (progress == iso1chargeProgressType_Start) { // Modified by JJS (2019.02.07)
	    exiIn.V2G_Message.Body.PowerDeliveryReq.ChargingProfile_isUsed = 1u;
	     // Must be initialized to 0
	    // == Charging Entries ==
	    //SetProfileEntry(profile, relative time, power, max phases)
        profile->ProfileEntry.arrayLen = 0; // must be 0
        SetProfileEntry(profile,   0, 15000, 3);
        SetProfileEntry(profile, 100, 20000, 3);
        SetProfileEntry(profile, 200, 10000, 3);
        SetProfileEntry(profile, 400,     0, 3);
	} else {
	    exiIn.V2G_Message.Body.PowerDeliveryReq.ChargingProfile_isUsed = 0;
	}
	err = v2g_request(conn, &exiIn, &exiOut);
    if (err != 0) {
        printf("power_delivery_request v2g_request error, exiting\n");
        return -1;
    }
    // === Validate response type ===
    if (exiOut.V2G_Message.Body.PowerDeliveryRes_isUsed != 1u) {
        printf("power_delivery_request: wrong response type\n");
        return -1;
    }
    // === Validate response code ===
    if (verify_response_code(exiOut.V2G_Message.Body.PowerDeliveryRes.ResponseCode) != 0) {
        printf("power_delivery_request: response NOT ok, code = %d\n", exiOut.V2G_Message.Body.PowerDeliveryRes.ResponseCode);
        return -1;
    }
	//printACEVSEStatus(&(exiOut.V2G_Message.Body.PowerDeliveryRes.AC_EVSEStatus));
    return 0;
}

int charging_status_request(evcc_conn_t *conn, ev_session_t *s)
{
    int err;
    struct iso1EXIDocument exiIn; // Modified by JJS (2019.02.07)
    struct iso1EXIDocument exiOut; // Modified by JJS (2019.02.07)
    struct iso1ChargingStatusResType *res = &exiOut.V2G_Message.Body.ChargingStatusRes; // Modified by JJS (2019.02.07)
    init_v2g_request(&exiIn, s);
	exiIn.V2G_Message.Body.ChargingStatusReq_isUsed = 1u;
	init_iso1ChargingStatusReqType(&exiIn.V2G_Message.Body.ChargingStatusReq); // Modified by JJS (2019.02.07)
	err = v2g_request(conn, &exiIn, &exiOut);
    if (err != 0) {
        printf("harging_status_request: unable to do v2g_request, exiting\n");
        return -1;
    }
    // === Validate response type ===
    if (exiOut.V2G_Message.Body.ChargingStatusRes_isUsed != 1u) {
        printf("charging_status_request: wrong response type\n");
        return -1;
    }
    // === Validate response code ===
    if (verify_response_code(res->ResponseCode) != 0) {
        printf("charging_status_request: authorization response NOT ok, code = %d\n", exiOut.V2G_Message.Body.ChargingStatusRes.ResponseCode);
        return -1;
    }
    if (res->AC_EVSEStatus.EVSENotification <= iso1EVSENotificationType_ReNegotiation) { // Modified by JJS (2019.02.07)
        s->evse_notification = res->AC_EVSEStatus.EVSENotification;
    }
    return 0;
}

int session_stop_request(evcc_conn_t *conn, ev_session_t *s)
{
    int err;
    struct iso1EXIDocument exiIn; // Modified by JJS (2019.02.07)
    struct iso1EXIDocument exiOut; // Modified by JJS (2019.02.07)
    init_v2g_request(&exiIn, s);
	exiIn.V2G_Message.Body.SessionStopReq_isUsed = 1u;
	init_iso1SessionStopReqType(&exiIn.V2G_Message.Body.SessionStopReq); // Modified by JJS (2019.02.07)
	err = v2g_request(conn, &exiIn, &exiOut);
    if (err != 0) {
        printf("harging_status_request: unable to do v2g_request, exiting\n");
        return -1;
    }
    // === Validate response type ===
    if (exiOut.V2G_Message.Body.SessionStopRes_isUsed != 1u) {
        printf("charging_status_request: wrong response type\n");
        return -1;
    }
    // === Validate response code ===
    if (verify_response_code(exiOut.V2G_Message.Body.SessionStopRes.ResponseCode) != 0) {
        printf("charging_status_request: authorization response NOT ok, code = %d\n", exiOut.V2G_Message.Body.SessionStopRes.ResponseCode);
        return -1;
    }
    return 0;
}
