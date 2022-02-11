//
// Created by Donal on 2022/2/11.
//

#ifndef MUPDF_INTERNAL_ASN1_H
#define MUPDF_INTERNAL_ASN1_H

int Internal_Asn1_WriteTL(
        unsigned long tagType,
        unsigned long length,
        unsigned char *destBuf,
        unsigned long nowOffset,
        unsigned long *afterOffset);

int Internal_Asn1_CountLength(
        unsigned long tagLen,
        unsigned long length,
        unsigned long dataLen,
        unsigned long *sumLen);

int Internal_GetAsn1TotalLength(
        unsigned char *srcBuf,
        unsigned long *length);

int Internal_Asn1_WriteOidByValue(
        unsigned char *data,
        unsigned long dataLen,
        unsigned char *destBuf,
        unsigned long nowOffset,
        unsigned long *afterOffset);

int Internal_Asn1_WriteLength(
        unsigned long length,
        unsigned char *destBuf,
        unsigned long nowOffset,
        unsigned long *afterOffset);

int Internal_Asn1_SkipTLV(
        unsigned long tagType,
        unsigned char *srcBuf,
        unsigned long nowOffset,
        unsigned long *afterOffset);

int Internal_Asn1_SkipTL(
        unsigned long tagType,
        unsigned char *srcBuf,
        unsigned long nowOffset,
        unsigned long *afterOffset);

int Internal_Asn1_SkipT(
        unsigned long tagType,
        unsigned char *srcBuf,
        unsigned long nowOffset,
        unsigned long *afterOffset);

int Internal_IsSM2Pkcs7Type(
        unsigned char *inData,
        unsigned long inDataLen);

int Internal_ReplacePkcs7OID(
        char *oidStr,
        unsigned char *input,
        unsigned long inputLen,
        unsigned char *output,
        unsigned long *outputLen);

int Internal_ReplaceSM2Pkcs7SignedOID(
        unsigned long flag,
        unsigned char *input,
        unsigned long inputLen,
        unsigned char *output,
        unsigned long *outputLen);


#endif //MUPDF_INTERNAL_ASN1_H
