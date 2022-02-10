//
// Created by Donal on 2022/1/25.
//

#include "internal_openssl_cert.h"

//parse ASN_STRING
int parseAsnString(ASN1_STRING *asn1String,char *buf,unsigned long *bufLen)
{
    unsigned char *tmp_data = NULL;
    int len;
    void *p = NULL;
    char *tmpStr = NULL;
    unsigned long inform;
    ASN1_STRING *pAsnStr = NULL;
    int i, j;
    int rv = 0;
    // LOGE("%d ",asn1String->type);
    switch (asn1String->type)
    {
        case V_ASN1_BMPSTRING:
            // LOGE("V_ASN1_BMPSTRING");
            len = ASN1_STRING_length(asn1String);
            // LOGE("V_ASN1_BMPSTRING len :%d", len);
            p = ASN1_STRING_data(asn1String);

            tmp_data = (unsigned char *)malloc(2*len+1024);
            if(NULL == tmp_data)
            {
                return -1;
            }
            memset(tmp_data,0,2*len+1024);
            // LOGE("tmp_data ");
#if defined(_WIN32)
            //BMPString(BigEnd) to UnicodeString(LittleEnd)
		for (j=0; j<len; j+=2)
		{
			tmp_data[j] = ((unsigned char*)p)[j+1];
			tmp_data[j+1] = ((unsigned char*)p)[j];
		}

#elif defined(_LINUX)
            // LOGE("_LINUX ");
		for (i=0,j=0; i<len; i+=2,j+=4)
		{
			tmp_data[j] = ((unsigned char*)p)[i+1];
			tmp_data[j+1] = ((unsigned char*)p)[i];
			tmp_data[j+2] = 0;
			tmp_data[j+3] = 0;
		}
		tmp_data[j] = 0;
		tmp_data[j+1] = 0;
		tmp_data[j+2] = 0;
		tmp_data[j+3] = 0;
         // LOGE("tmp_data end ");
#elif defined(_IOS)
            for (i=0,j=0; i<len; i+=2,j+=4)
            {
                tmp_data[j] = ((unsigned char*)p)[i+1];
                tmp_data[j+1] = ((unsigned char*)p)[i];
                tmp_data[j+2] = 0;
                tmp_data[j+3] = 0;
            }
            tmp_data[j] = 0;
            tmp_data[j+1] = 0;
            tmp_data[j+2] = 0;
            tmp_data[j+3] = 0;

#else
            return -1;
#endif

            //UnicodeString(LittleEnd) to GB2312
            rv = UnicodeToGb2312(&tmpStr, (wchar_t *)tmp_data);
            if(0!=rv)
                return -1;

            memcpy(buf,tmpStr,strlen(tmpStr));
            *bufLen = strlen(tmpStr);
            // LOGE("bufLen len:%d", *bufLen);
            free(tmp_data);
            free(tmpStr);
            break;
        case V_ASN1_UTF8STRING:
            // LOGE("V_ASN1_UTF8STRING ");
            len = ASN1_STRING_length(asn1String);
            p = ASN1_STRING_data(asn1String);

            //UTF8 to GB2312
            // Utf8ToGb2312(&tmpStr, p);
            memcpy(buf,p,len);
            *bufLen = len;
            break;
        default:
            // LOGE("default ");
            len = ASN1_STRING_length(asn1String);
            p = ASN1_STRING_data(asn1String);
            memcpy(buf,p,len);
            *bufLen = len;

            //to utf8
// 		if(V_ASN1_PRINTABLESTRING == asn1String->type) inform = MBSTRING_ASC;
// 		else if(V_ASN1_IA5STRING == asn1String->type) inform = MBSTRING_ASC;
// 		else if(V_ASN1_T61STRING == asn1String->type) inform = MBSTRING_ASC;
// 		else if(V_ASN1_UNIVERSALSTRING == asn1String->type) inform = MBSTRING_UNIV;
// 		else inform = MBSTRING_UTF8;

// 		ASN1_mbstring_copy(&pAsnStr, p, len, inform, B_ASN1_UTF8STRING);

// 		len = ASN1_STRING_length(pAsnStr);
// 		p = ASN1_STRING_data(pAsnStr);
// LOGE("default Utf8ToGb2312");
// 		//UTF8 to GB2312
// 		Utf8ToGb2312(&tmpStr, p);

// 		memcpy(buf,tmpStr,strlen(tmpStr));
// 		*bufLen = strlen(tmpStr);
// 		free(tmpStr);
// 		ASN1_STRING_free(pAsnStr);

            break;
    }
    return 0;
}

int Internal_Do_GetCertDN(
        X509 *xcert,
        unsigned long type,
        unsigned char *info,
        unsigned long *infoLen) {
    X509_NAME *name = NULL;
    X509_NAME_ENTRY *ne;
    ASN1_STRING *asn1String = NULL;
    int i = 0;
    unsigned char oid[128];
    int ret = -1;
    unsigned char buf[1024];
    unsigned long bufLen = 1024;
    unsigned long num = 0;
    unsigned long len = 0;
    char oidName[128];

    if (INTERNAL_GET_CERT_ISSUER_CN == type || INTERNAL_GET_CERT_SUBJECT_CN == type)
        strcpy(oidName, "commonName");
    else if (INTERNAL_GET_CERT_ISSUER_O == type || INTERNAL_GET_CERT_SUBJECT_O == type)
        strcpy(oidName, "organizationName");
    else if (INTERNAL_GET_CERT_ISSUER_OU == type || INTERNAL_GET_CERT_SUBJECT_OU == type)
        strcpy(oidName, "organizationalUnitName");
    else if (INTERNAL_GET_CERT_SUBJECT_EMAIL == type)
        strcpy(oidName, "emailAddress");
    else {
        return -1;
    }

    if ((INTERNAL_GET_CERT_ISSUER_CN == type) || (INTERNAL_GET_CERT_ISSUER_O == type) ||
        (INTERNAL_GET_CERT_ISSUER_OU == type))
        name = X509_get_issuer_name(xcert);
    else
        name = X509_get_subject_name(xcert);

    for (i = 0; i < X509_NAME_entry_count(name); i++) {
        memset(buf, 0, bufLen);

        ne = X509_NAME_get_entry(name, i);//sk_X509_NAME_ENTRY_value(name->entries,i);
        OBJ_obj2txt(oid, 128, X509_NAME_ENTRY_get_object(ne), 0);
        asn1String = X509_NAME_ENTRY_get_data(ne);
        if (0 == strcmp(oid, oidName)) {
            int tmpRe = parseAsnString(asn1String, buf, &bufLen);
            if (tmpRe != 0) {
                continue;
            }
            if (num != 0) {
                info[len] = '\n';
                len += 1;
            }
            memcpy(info + len, buf, bufLen);
            len += bufLen;
            num++;
        }
    }

    if (0 == num) {
        return -1;
    }

    info[len] = '\0';
    *infoLen = len;
    return 0;
}

//get signature algorithm of certificate
int Internal_Do_GetCertSignatureAlgo(
        X509 *xcert,
        unsigned char *signAlg,
        unsigned long *signAlgLen) {
    i2t_ASN1_OBJECT(signAlg, 1024, X509_get0_tbs_sigalg(xcert)->algorithm);
    *signAlgLen = strlen(signAlg);
    return 0;

}

int toLocalTime(
        int hourDiff,
        int y,
        int M,
        int d,
        int h,
        int *Local_y,
        int *Local_M,
        int *Local_d,
        int *Local_h
) {
    int year = y, month = M, day = d, hour = h;
    int days[] = {0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

    if (year < 1)
        return -1;

    if (month < 1 || month > 12)
        return -2;

    if (day < 1 || day > 31)
        return -3;

    if (hour < 0 || hour > 24)
        return -4;

    if ((year % 400 == 0) || ((year % 100 != 0) && (year % 4 == 0))) // run year
        days[2] = 29;

    hour = hour + hourDiff;

    if (hour >= 24) {
        hour = hour - 24;
        day++;

        if (day > days[month]) {
            day = 1;
            month++;
        }

        if (month > 12) {
            year++;
            month = 1;
        }
    }

    *Local_y = year;
    *Local_M = month;
    *Local_d = day;
    *Local_h = hour;

    return 0;
}

//parse asnTime
int parseASNTime(ASN1_TIME *tm, unsigned char *buf, unsigned long *bufLen) {
    char *v;
    int gmt = 0;
    int i;
    int y = 0, M = 0, d = 0, h = 0, m = 0, s = 0;
    char *f = NULL;
    int f_len = 0;
    int l;

    int ret = 0;
    int Local_y = 0;
    int Local_M = 0;
    int Local_d = 0;
    int Local_h = 0;

    if (tm->type == V_ASN1_UTCTIME) {
        i = tm->length;
        v = tm->data;

        if (i < 10) goto err;
        if (v[i - 1] == 'Z') gmt = 1;
        for (i = 0; i < 10; i++)
            if ((v[i] > '9') || (v[i] < '0')) goto err;
        y = (v[0] - '0') * 10 + (v[1] - '0');
        if (y < 50) y += 100;
        M = (v[2] - '0') * 10 + (v[3] - '0');
        if ((M > 12) || (M < 1)) goto err;
        d = (v[4] - '0') * 10 + (v[5] - '0');
        h = (v[6] - '0') * 10 + (v[7] - '0');
        m = (v[8] - '0') * 10 + (v[9] - '0');
        if (tm->length >= 12 &&
            (v[10] >= '0') && (v[10] <= '9') &&
            (v[11] >= '0') && (v[11] <= '9'))
            s = (v[10] - '0') * 10 + (v[11] - '0');

/*
		h += 8;   //change to beijing time

		if(h>=24)
		{
			d += 1;
			h -= 24;
		}
		sprintf(buf,"%2d-%2d-%02d:%02d:%02d:%02d",y+1900,M,d,h,m,s);
*/

        ret = toLocalTime(
                8, //change to beijing time
                y,
                M,
                d,
                h,
                &Local_y,
                &Local_M,
                &Local_d,
                &Local_h
        );
        if (0 != ret)
            goto err;

        sprintf(buf, "%2d-%2d-%02d:%02d:%02d:%02d", Local_y + 1900, Local_M, Local_d, Local_h, m, s);

        *bufLen = strlen(buf);
        return 0;
    }
    if (tm->type == V_ASN1_GENERALIZEDTIME) {
        i = tm->length;
        v = (char *) tm->data;

        if (i < 12) goto err;
        if (v[i - 1] == 'Z') gmt = 1;
        for (i = 0; i < 12; i++)
            if ((v[i] > '9') || (v[i] < '0')) goto err;
        y = (v[0] - '0') * 1000 + (v[1] - '0') * 100 + (v[2] - '0') * 10 + (v[3] - '0');
        M = (v[4] - '0') * 10 + (v[5] - '0');
        if ((M > 12) || (M < 1)) goto err;
        d = (v[6] - '0') * 10 + (v[7] - '0');
        h = (v[8] - '0') * 10 + (v[9] - '0');
        m = (v[10] - '0') * 10 + (v[11] - '0');
        if (tm->length >= 14 &&
            (v[12] >= '0') && (v[12] <= '9') &&
            (v[13] >= '0') && (v[13] <= '9')) {
            s = (v[12] - '0') * 10 + (v[13] - '0');

            // Check for fractions of seconds.
            if (tm->length >= 15 && v[14] == '.') {
                l = tm->length;
                f = &v[14];    /* The decimal point. */
                f_len = 1;
                while (14 + f_len < l && f[f_len] >= '0' && f[f_len] <= '9')
                    ++f_len;
            }
        }
/*
		h += 8;   //change to beijing time

		if(h>=24)
		{
			d += 1;
			h -= 24;
		}

		sprintf(buf,"%2d-%2d-%02d %02d %02d:%2d",y+1900,M-1,d,h,m,s);
*/
        ret = toLocalTime(
                8, //change to beijing time
                y,
                M,
                d,
                h,
                &Local_y,
                &Local_M,
                &Local_d,
                &Local_h
        );
        if (0 != ret)
            goto err;

        sprintf(buf, "%2d-%2d-%02d:%02d:%02d:%02d", Local_y + 1900, Local_M, Local_d, Local_h, m, s);

        *bufLen = strlen(buf);
        return 0;
    }

    err:
    return -1;
}

int Internal_Do_GetCertValidTime(
        X509 *xcert,
        unsigned char *startTime,
        unsigned long *startTimeLen,
        unsigned char *endTime,
        unsigned long *endTimeLen) {
    ASN1_TIME *notbefore = NULL;
    ASN1_TIME *notafter = NULL;
    unsigned long offset = 0;
    unsigned long len;

    notbefore = X509_get_notBefore(xcert);
    notafter = X509_get_notAfter(xcert);

    parseASNTime(notbefore, startTime, startTimeLen);
    startTime[*startTimeLen] = '\0';

    parseASNTime(notafter, endTime, endTimeLen);
    endTime[*endTimeLen] = '\0';

    return 0;
}

//get serial of certificate
int Internal_Do_GetCertSerial(
        X509 *xcert,
        unsigned char *serial,
        unsigned long *serialLen) {
    ASN1_INTEGER *sN = NULL;
    int i, j;

    sN = X509_get_serialNumber(xcert);
    if (NULL == sN) {
        return -1;
    }

    j = 0;
    for (i = 0; i < sN->length; i++) {
        sprintf(&serial[j], "%02x", sN->data[i]);
        j += 2;
    }
    serial[j] = '\0';
    *serialLen = strlen(serial);
    return 0;
}

