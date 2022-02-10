//
// Created by Donal on 2022/1/25.
//

#ifndef MUPDF_INTERNAL_OPENSSL_CERT_H
#define MUPDF_INTERNAL_OPENSSL_CERT_H

#include <openssl/bio.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define INTERNAL_GET_CERT_INFO 0x0005
#define INTERNAL_GET_CERT_VERSION 0x0006
#define INTERNAL_GET_CERT_SERIAL 0x0007
#define INTERNAL_GET_CERT_SIGNATURE_ALGO 0x0008
#define INTERNAL_GET_CERT_ISSUER 0x0009
#define INTERNAL_GET_CERT_VALID_TIME 0x0010
#define INTERNAL_GET_CERT_SUBJECT 0x0011
#define INTERNAL_GET_CERT_PUBLIC_KEY 0x0012
#define INTERNAL_GET_CERT_EXTENSIONS 0x0013

#define INTERNAL_GET_CERT_ISSUER_CN		0x0021
#define INTERNAL_GET_CERT_ISSUER_O		0X0022
#define INTERNAL_GET_CERT_ISSUER_OU		0X0023
#define INTERNAL_GET_CERT_SUBJECT_CN	0x0031
#define INTERNAL_GET_CERT_SUBJECT_O		0X0032
#define INTERNAL_GET_CERT_SUBJECT_OU	0X0033
#define INTERNAL_GET_CERT_SUBJECT_EMAIL 0X0034

int Internal_Do_GetCertDN(
        X509 *xcert,
        unsigned long type,
        unsigned char *info,
        unsigned long *infoLen);

int Internal_Do_GetCertSignatureAlgo(
        X509 *xcert,
        unsigned char *signAlg,
        unsigned long *signAlgLen);

int Internal_Do_GetCertValidTime(
        X509 *xcert,
        unsigned char *startTime,
        unsigned long *startTimeLen,
        unsigned char *endTime,
        unsigned long *endTimeLen);

#endif //MUPDF_INTERNAL_OPENSSL_CERT_H
