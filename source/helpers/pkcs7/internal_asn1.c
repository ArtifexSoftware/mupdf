//
// Created by Donal on 2022/2/11.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <time.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/pkcs7.h>
#include "internal_asn1.h"

//SM2 OID
char *s_saf_sm1OidStr = "1.2.156.10197.1.102";
char *s_saf_sm2EnvelopedOidStr = "1.2.156.10197.6.1.4.2.3";
char *s_saf_sm2SignedOidStr = "1.2.156.10197.6.1.4.2.2";
char *s_saf_sm2DataOidStr = "1.2.156.10197.6.1.4.2.1";
char *s_saf_sm2SignAlgOidStr = "1.2.156.10197.1.301.1";
char *s_saf_sm2EncryptOidStr = "1.2.156.10197.1.301.3";
char *s_saf_sm3HashWithKeyOidStr = "1.2.156.10197.1.401.2";
char *s_saf_sm3HashOidStr = "1.2.156.10197.1.401";
char *s_saf_p7DataOidStr = "1.2.840.113549.1.7.1";
char *s_saf_p7EnvelopedOidStr = "1.2.840.113549.1.7.3";
char *s_saf_p7SignedOidStr = "1.2.840.113549.1.7.2";
char *s_saf_sha1OidStr = "1.3.14.3.2.26";
char *s_saf_sha256OidStr = "2.16.840.1.101.3.4.2.1";

int Internal_Asn1_WriteTL(
        unsigned long tagType,
        unsigned long length,
        unsigned char *destBuf,
        unsigned long nowOffset,
        unsigned long *afterOffset)
{

    *(destBuf + nowOffset) = (unsigned char)tagType;
    nowOffset++;

    return Internal_Asn1_WriteLength(length,destBuf,nowOffset,afterOffset);
}

int Internal_Asn1_CountLength(
        unsigned long tagLen,
        unsigned long length,
        unsigned long dataLen,
        unsigned long *sumLen)
{
    unsigned long buffLen;
    if (length <= 0x7f)
    {
        buffLen = 1;
    }
    else
    {
        if (length <= 0x0ff)
        {
            buffLen = 2;
        }
        else
        {
            if (length <= 0x0ffff)
            {
                buffLen = 3;
            }
            else
            {
                if (length <= 0xffffff)
                {
                    buffLen = 4;
                }
                else
                {
                    buffLen = 5;
                }
            }
        }
    }
    buffLen += tagLen;
    buffLen += dataLen;
    *sumLen = buffLen;
    return 0;
}

int Internal_GetAsn1TotalLength(
        unsigned char *srcBuf,
        unsigned long *length)
{
    unsigned char *p;
    unsigned long lenCount,len;

    p = srcBuf + 1;

    *length = 2;

    if (p[0] & 0x80)
    {
        lenCount = p[0] & 0x7f;

        *length += lenCount;

        p++;

        len = 0;
        while (lenCount--)
        {
            len <<= 8;
            len += *p;
            p++;
        }
        *length += len;
    }
    else
    {
        *length += (unsigned long)p[0];
    }

    return 0;
}

int Internal_Asn1_WriteOidByValue(
        unsigned char *data,
        unsigned long dataLen,
        unsigned char *destBuf,
        unsigned long nowOffset,
        unsigned long *afterOffset)
{
    int rv;

    destBuf[nowOffset] = 0x06;
    nowOffset++;

    rv = Internal_Asn1_WriteLength(dataLen,destBuf,nowOffset,afterOffset);
    if (0 != rv)
    {
        return rv;
    }
    nowOffset = *afterOffset;

    memcpy(destBuf + nowOffset,data,dataLen);
    *afterOffset = nowOffset + dataLen;

    return 0;
}

int Internal_Asn1_WriteLength(
        unsigned long length,
        unsigned char *destBuf,
        unsigned long nowOffset,
        unsigned long *afterOffset)
{

    if (length <= 0x7f)
    {
        *(destBuf + nowOffset) = (unsigned char)length;
        *afterOffset = nowOffset + 1;
    }
    else
    {
        if (length <= 0x0ff)
        {
            *(destBuf + nowOffset) = 0x81;
            *(destBuf + nowOffset + 1) = (unsigned char)length;
            *afterOffset = nowOffset + 2;
        }
        else
        {
            if (length <= 0x0ffff)
            {
                *(destBuf + nowOffset) = 0x82;
                *(destBuf + nowOffset + 1) = (unsigned char)(length >> 8);
                *(destBuf + nowOffset + 2) = (unsigned char)length;
                *afterOffset = nowOffset + 3;
            }
            else
            {
                if (length <= 0xffffff)
                {
                    *(destBuf + nowOffset) = 0x83;
                    *(destBuf + nowOffset + 1) = (unsigned char)(length >> 16);
                    *(destBuf + nowOffset + 2) = (unsigned char)(length >> 8);
                    *(destBuf + nowOffset + 3) = (unsigned char)length;
                    *afterOffset = nowOffset + 4;
                }
                else
                {
                    *(destBuf + nowOffset) = 0x84;
                    *(destBuf + nowOffset + 1) = (unsigned char)(length >> 24);
                    *(destBuf + nowOffset + 2) = (unsigned char)(length >> 16);
                    *(destBuf + nowOffset + 3) = (unsigned char)(length >> 8);
                    *(destBuf + nowOffset + 4) = (unsigned char)length;
                    *afterOffset = nowOffset + 5;
                }
            }
        }
    }

    return 0;
}

int Internal_Asn1_SkipTLV(
        unsigned long tagType,
        unsigned char *srcBuf,
        unsigned long nowOffset,
        unsigned long *afterOffset)
{
    unsigned char *p;
    unsigned long i,lenCount,len;

    p = srcBuf + nowOffset;

    if (tagType && (tagType != *p))
    {
        return -1;
    }

    p++;

    if (*p & 0x80)
    {
        lenCount = *p & 0x7f;

        p++;

        len = 0;
        for (i=0;i<lenCount;i++)
        {
            len <<= 8;
            len += *p;
            p++;
        }

        *afterOffset = nowOffset + 2 + lenCount + len;
    }
    else
    {
        len = (unsigned long)*p;
        *afterOffset = nowOffset + 2 + len;
    }

    return 0;
}

int Internal_Asn1_SkipTL(
        unsigned long tagType,
        unsigned char *srcBuf,
        unsigned long nowOffset,
        unsigned long *afterOffset)
{
    unsigned char *p;
    unsigned long lenCount;

    p = srcBuf + nowOffset;


    if (tagType && (tagType != *p))
    {
        return -1;
    }

    p++;

    if (*p & 0x80)
    {
        lenCount = *p & 0x7f;
        *afterOffset = nowOffset + 2 + lenCount;
    }
    else
    {
        *afterOffset = nowOffset + 2;
    }

    return 0;
}

int Internal_Asn1_SkipT(
        unsigned long tagType,
        unsigned char *srcBuf,
        unsigned long nowOffset,
        unsigned long *afterOffset)
{
    unsigned char *p;

    p = srcBuf + nowOffset;

    if (tagType && (tagType != *p))
    {
        return -1;
    }

    *afterOffset = nowOffset + 1;

    return 0;
}

int Internal_IsSM2Pkcs7Type(
        unsigned char *inData,
        unsigned long inDataLen)
{
    PKCS7 *p7 = NULL;
    char *pp = inData;
    char buf[128];

    p7 = d2i_PKCS7(NULL, &pp, (int)inDataLen);
    if(NULL == p7)
        return -1;

    OBJ_obj2txt(buf,128,p7->type,1);

    PKCS7_free(p7);
    if(strncmp(buf,s_saf_sm2SignedOidStr,strlen(s_saf_sm2SignedOidStr)) != 0)
        return -1;
    else
        return 0;
}

int Internal_ReplacePkcs7OID(
        char *oidStr,
        unsigned char *input,
        unsigned long inputLen,
        unsigned char *output,
        unsigned long *outputLen)
{
    unsigned char oidDer[64];
    unsigned long oidDerLen;
    unsigned long nowOffset = 0, afterOffset = 0;
    unsigned long contextStart = 0;
    unsigned long contextLen;
    unsigned long valueLen;

    unsigned long dataSequenceLen = 0;
    unsigned long dataOIDLen = 0;


    oidDerLen = a2d_ASN1_OBJECT(oidDer,64,oidStr,-1);

    Internal_GetAsn1TotalLength(input,&dataSequenceLen);

    Internal_GetAsn1TotalLength(input+2,&dataOIDLen);

    Internal_Asn1_SkipTL(0x30,input,nowOffset,&afterOffset);
    nowOffset = afterOffset;

    Internal_Asn1_SkipTLV(0x06,input,nowOffset,&afterOffset);

    //if data Sequence content only dataOID, so Context not exist. This is PKCS#7 sign without data
    if(dataSequenceLen == dataOIDLen+2)
    {
        contextLen = 0;
    }
    else
    {
        contextStart = afterOffset;

        Internal_GetAsn1TotalLength(input+contextStart,&contextLen);

    }

    valueLen = 2 + oidDerLen + contextLen;

    nowOffset = 0;
    Internal_Asn1_WriteTL(0x30,valueLen,output,nowOffset,&afterOffset);
    nowOffset = afterOffset;

    Internal_Asn1_WriteOidByValue(oidDer,oidDerLen,output,nowOffset,&afterOffset);
    nowOffset = afterOffset;

    //if data Sequence content only dataOID, so Context not exist. This is PKCS#7 sign without data
    if(dataSequenceLen == dataOIDLen+2)
    {
        *outputLen = nowOffset + contextLen;
    }
    else
    {
        memcpy(output+nowOffset,input+contextStart,contextLen);
        *outputLen = nowOffset + contextLen;
    }

    return 0;
}

int Internal_ReplaceSM2Pkcs7SignedOID(
        unsigned long flag,
        unsigned char *input,
        unsigned long inputLen,
        unsigned char *output,
        unsigned long *outputLen)
{
    unsigned char signedOidDer[64];
    unsigned long signedOidDerLen;
    char dataOidStr[64];
    unsigned long nowOffset = 0, afterOffset = 0;

    unsigned char *nContentInfo = NULL;
    unsigned long nContentInfoLen;

    unsigned long contextLen;
    unsigned long sequenceLen;
    unsigned long offset1,offset2,offset3;
    unsigned long len1,len2,len3;
    unsigned long valueLen;

    //flag=1,P7 OID replaced by SM2 OID
    if(1 == flag)
    {
        signedOidDerLen = a2d_ASN1_OBJECT(signedOidDer,64,s_saf_sm2SignedOidStr,-1);
        strcpy(dataOidStr,s_saf_sm2DataOidStr);
    }

        //flag=0, SM2 OID replaced by P7 OID
    else if(0 == flag)
    {
        signedOidDerLen = a2d_ASN1_OBJECT(signedOidDer,64,s_saf_p7SignedOidStr,-1);
        strcpy(dataOidStr,s_saf_p7DataOidStr);
    }
    else
    {
        return -1;
    }

    nContentInfo = (unsigned char *)malloc(inputLen);
    if(NULL == nContentInfo)
    {
        return -1;
    }

    //skip T and L of sequence
    Internal_Asn1_SkipTL(0x30,input,nowOffset,&afterOffset);
    nowOffset = afterOffset;

    //skip TLV of OID
    Internal_Asn1_SkipTLV(0x06,input,nowOffset,&afterOffset);
    nowOffset = afterOffset;

    //skip T and L of context
    Internal_Asn1_SkipTL(0xA0,input,nowOffset,&afterOffset);
    nowOffset = afterOffset;

    Internal_GetAsn1TotalLength(input+afterOffset,&sequenceLen);

    Internal_Asn1_SkipTL(0x30,input,nowOffset,&afterOffset);
    nowOffset = afterOffset;

    offset1 = afterOffset;

    Internal_Asn1_SkipTLV(0x02,input,nowOffset,&afterOffset);
    nowOffset = afterOffset;

    Internal_Asn1_SkipTLV(0x31,input,nowOffset,&afterOffset);
    nowOffset = afterOffset;

    offset2 = afterOffset;
    len1 = afterOffset - offset1;

    Internal_GetAsn1TotalLength(input+afterOffset,&len2);

    Internal_ReplacePkcs7OID(dataOidStr,input+afterOffset,len2,nContentInfo,&nContentInfoLen);

    Internal_Asn1_SkipTLV(0x30,input,nowOffset,&afterOffset);
    nowOffset = afterOffset;

    offset3 = afterOffset;

    Internal_Asn1_SkipTLV(0xA0,input,nowOffset,&afterOffset);
    nowOffset = afterOffset;

    Internal_Asn1_SkipTLV(0x31,input,nowOffset,&afterOffset);
    nowOffset = afterOffset;

    len3 = afterOffset - offset3;

    sequenceLen = sequenceLen -len2 + nContentInfoLen;

    Internal_Asn1_CountLength(1,sequenceLen,sequenceLen,&contextLen);

    valueLen = contextLen+signedOidDerLen + 2;

    nowOffset = 0;
    Internal_Asn1_WriteTL(0x30,valueLen,output,nowOffset,&afterOffset);
    nowOffset = afterOffset;

    Internal_Asn1_WriteOidByValue(signedOidDer,signedOidDerLen,output,nowOffset,&afterOffset);
    nowOffset = afterOffset;

    Internal_Asn1_WriteTL(0xA0,sequenceLen,output,nowOffset,&afterOffset);
    nowOffset = afterOffset;

    Internal_Asn1_WriteTL(0x30,len1+nContentInfoLen+len3,output,nowOffset,&afterOffset);
    nowOffset = afterOffset;

    memcpy(output+nowOffset,input+offset1,len1);
    nowOffset += len1;

    memcpy(output+nowOffset,nContentInfo,nContentInfoLen);
    nowOffset += nContentInfoLen;

    memcpy(output+nowOffset,input+offset3,len3);
    nowOffset += len3;

    *outputLen = nowOffset;

    if(nContentInfo)
    {
        free(nContentInfo);
        nContentInfo = NULL;
    }
    return 0;
}