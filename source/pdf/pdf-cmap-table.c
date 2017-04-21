#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

#include <string.h>

#ifdef NOCJK
#define CJK_CMAPS 0
#endif

#ifndef CJK_CMAPS
#define CJK_CMAPS 1
#endif

#ifndef EXTRA_CMAPS
#define EXTRA_CMAPS 0
#endif
#ifndef UTF8_CMAPS
#define UTF8_CMAPS 0
#endif
#ifndef UTF32_CMAPS
#define UTF32_CMAPS 0
#endif

#if CJK_CMAPS

extern pdf_cmap pdf_cmap_83pv_RKSJ_H;
extern pdf_cmap pdf_cmap_90ms_RKSJ_H;
extern pdf_cmap pdf_cmap_90ms_RKSJ_V;
extern pdf_cmap pdf_cmap_90msp_RKSJ_H;
extern pdf_cmap pdf_cmap_90msp_RKSJ_V;
extern pdf_cmap pdf_cmap_90pv_RKSJ_H;
extern pdf_cmap pdf_cmap_Add_RKSJ_H;
extern pdf_cmap pdf_cmap_Add_RKSJ_V;
extern pdf_cmap pdf_cmap_Adobe_CNS1_UCS2;
extern pdf_cmap pdf_cmap_Adobe_GB1_UCS2;
extern pdf_cmap pdf_cmap_Adobe_Japan1_UCS2;
extern pdf_cmap pdf_cmap_Adobe_Korea1_UCS2;
extern pdf_cmap pdf_cmap_B5pc_H;
extern pdf_cmap pdf_cmap_B5pc_V;
extern pdf_cmap pdf_cmap_CNS_EUC_H;
extern pdf_cmap pdf_cmap_CNS_EUC_V;
extern pdf_cmap pdf_cmap_ETen_B5_H;
extern pdf_cmap pdf_cmap_ETen_B5_V;
extern pdf_cmap pdf_cmap_ETenms_B5_H;
extern pdf_cmap pdf_cmap_ETenms_B5_V;
extern pdf_cmap pdf_cmap_EUC_H;
extern pdf_cmap pdf_cmap_EUC_V;
extern pdf_cmap pdf_cmap_Ext_RKSJ_H;
extern pdf_cmap pdf_cmap_Ext_RKSJ_V;
extern pdf_cmap pdf_cmap_GBK2K_H;
extern pdf_cmap pdf_cmap_GBK2K_V;
extern pdf_cmap pdf_cmap_GBK_EUC_H;
extern pdf_cmap pdf_cmap_GBK_EUC_V;
extern pdf_cmap pdf_cmap_GBKp_EUC_H;
extern pdf_cmap pdf_cmap_GBKp_EUC_V;
extern pdf_cmap pdf_cmap_GB_EUC_H;
extern pdf_cmap pdf_cmap_GB_EUC_V;
extern pdf_cmap pdf_cmap_GBpc_EUC_H;
extern pdf_cmap pdf_cmap_GBpc_EUC_V;
extern pdf_cmap pdf_cmap_H;
extern pdf_cmap pdf_cmap_HKscs_B5_H;
extern pdf_cmap pdf_cmap_HKscs_B5_V;
extern pdf_cmap pdf_cmap_KSC_EUC_H;
extern pdf_cmap pdf_cmap_KSC_EUC_V;
extern pdf_cmap pdf_cmap_KSCms_UHC_H;
extern pdf_cmap pdf_cmap_KSCms_UHC_HW_H;
extern pdf_cmap pdf_cmap_KSCms_UHC_HW_V;
extern pdf_cmap pdf_cmap_KSCms_UHC_V;
extern pdf_cmap pdf_cmap_KSCpc_EUC_H;
extern pdf_cmap pdf_cmap_UniCNS_UCS2_H;
extern pdf_cmap pdf_cmap_UniCNS_UCS2_V;
extern pdf_cmap pdf_cmap_UniCNS_UTF16_H;
extern pdf_cmap pdf_cmap_UniCNS_UTF16_V;
extern pdf_cmap pdf_cmap_UniCNS_X;
extern pdf_cmap pdf_cmap_UniGB_UCS2_H;
extern pdf_cmap pdf_cmap_UniGB_UCS2_V;
extern pdf_cmap pdf_cmap_UniGB_UTF16_H;
extern pdf_cmap pdf_cmap_UniGB_UTF16_V;
extern pdf_cmap pdf_cmap_UniGB_X;
extern pdf_cmap pdf_cmap_UniJIS_UCS2_H;
extern pdf_cmap pdf_cmap_UniJIS_UCS2_HW_H;
extern pdf_cmap pdf_cmap_UniJIS_UCS2_HW_V;
extern pdf_cmap pdf_cmap_UniJIS_UCS2_V;
extern pdf_cmap pdf_cmap_UniJIS_UTF16_H;
extern pdf_cmap pdf_cmap_UniJIS_UTF16_V;
extern pdf_cmap pdf_cmap_UniJIS_X16;
extern pdf_cmap pdf_cmap_UniJIS_X;
extern pdf_cmap pdf_cmap_UniKS_UCS2_H;
extern pdf_cmap pdf_cmap_UniKS_UCS2_V;
extern pdf_cmap pdf_cmap_UniKS_UTF16_H;
extern pdf_cmap pdf_cmap_UniKS_UTF16_V;
extern pdf_cmap pdf_cmap_UniKS_X;
extern pdf_cmap pdf_cmap_V;

struct table { const char *name; pdf_cmap *cmap; };

static const struct table table_cjk[] =
{
	{"83pv-RKSJ-H",&pdf_cmap_83pv_RKSJ_H},
	{"90ms-RKSJ-H",&pdf_cmap_90ms_RKSJ_H},
	{"90ms-RKSJ-V",&pdf_cmap_90ms_RKSJ_V},
	{"90msp-RKSJ-H",&pdf_cmap_90msp_RKSJ_H},
	{"90msp-RKSJ-V",&pdf_cmap_90msp_RKSJ_V},
	{"90pv-RKSJ-H",&pdf_cmap_90pv_RKSJ_H},
	{"Add-RKSJ-H",&pdf_cmap_Add_RKSJ_H},
	{"Add-RKSJ-V",&pdf_cmap_Add_RKSJ_V},
	{"Adobe-CNS1-UCS2",&pdf_cmap_Adobe_CNS1_UCS2},
	{"Adobe-GB1-UCS2",&pdf_cmap_Adobe_GB1_UCS2},
	{"Adobe-Japan1-UCS2",&pdf_cmap_Adobe_Japan1_UCS2},
	{"Adobe-Korea1-UCS2",&pdf_cmap_Adobe_Korea1_UCS2},
	{"B5pc-H",&pdf_cmap_B5pc_H},
	{"B5pc-V",&pdf_cmap_B5pc_V},
	{"CNS-EUC-H",&pdf_cmap_CNS_EUC_H},
	{"CNS-EUC-V",&pdf_cmap_CNS_EUC_V},
	{"ETen-B5-H",&pdf_cmap_ETen_B5_H},
	{"ETen-B5-V",&pdf_cmap_ETen_B5_V},
	{"ETenms-B5-H",&pdf_cmap_ETenms_B5_H},
	{"ETenms-B5-V",&pdf_cmap_ETenms_B5_V},
	{"EUC-H",&pdf_cmap_EUC_H},
	{"EUC-V",&pdf_cmap_EUC_V},
	{"Ext-RKSJ-H",&pdf_cmap_Ext_RKSJ_H},
	{"Ext-RKSJ-V",&pdf_cmap_Ext_RKSJ_V},
	{"GB-EUC-H",&pdf_cmap_GB_EUC_H},
	{"GB-EUC-V",&pdf_cmap_GB_EUC_V},
	{"GBK-EUC-H",&pdf_cmap_GBK_EUC_H},
	{"GBK-EUC-V",&pdf_cmap_GBK_EUC_V},
	{"GBK2K-H",&pdf_cmap_GBK2K_H},
	{"GBK2K-V",&pdf_cmap_GBK2K_V},
	{"GBKp-EUC-H",&pdf_cmap_GBKp_EUC_H},
	{"GBKp-EUC-V",&pdf_cmap_GBKp_EUC_V},
	{"GBpc-EUC-H",&pdf_cmap_GBpc_EUC_H},
	{"GBpc-EUC-V",&pdf_cmap_GBpc_EUC_V},
	{"H",&pdf_cmap_H},
	{"HKscs-B5-H",&pdf_cmap_HKscs_B5_H},
	{"HKscs-B5-V",&pdf_cmap_HKscs_B5_V},
	{"KSC-EUC-H",&pdf_cmap_KSC_EUC_H},
	{"KSC-EUC-V",&pdf_cmap_KSC_EUC_V},
	{"KSCms-UHC-H",&pdf_cmap_KSCms_UHC_H},
	{"KSCms-UHC-HW-H",&pdf_cmap_KSCms_UHC_HW_H},
	{"KSCms-UHC-HW-V",&pdf_cmap_KSCms_UHC_HW_V},
	{"KSCms-UHC-V",&pdf_cmap_KSCms_UHC_V},
	{"KSCpc-EUC-H",&pdf_cmap_KSCpc_EUC_H},
	{"UniCNS-UCS2-H",&pdf_cmap_UniCNS_UCS2_H},
	{"UniCNS-UCS2-V",&pdf_cmap_UniCNS_UCS2_V},
	{"UniCNS-UTF16-H",&pdf_cmap_UniCNS_UTF16_H},
	{"UniCNS-UTF16-V",&pdf_cmap_UniCNS_UTF16_V},
	{"UniCNS-X",&pdf_cmap_UniCNS_X},
	{"UniGB-UCS2-H",&pdf_cmap_UniGB_UCS2_H},
	{"UniGB-UCS2-V",&pdf_cmap_UniGB_UCS2_V},
	{"UniGB-UTF16-H",&pdf_cmap_UniGB_UTF16_H},
	{"UniGB-UTF16-V",&pdf_cmap_UniGB_UTF16_V},
	{"UniGB-X",&pdf_cmap_UniGB_X},
	{"UniJIS-UCS2-H",&pdf_cmap_UniJIS_UCS2_H},
	{"UniJIS-UCS2-HW-H",&pdf_cmap_UniJIS_UCS2_HW_H},
	{"UniJIS-UCS2-HW-V",&pdf_cmap_UniJIS_UCS2_HW_V},
	{"UniJIS-UCS2-V",&pdf_cmap_UniJIS_UCS2_V},
	{"UniJIS-UTF16-H",&pdf_cmap_UniJIS_UTF16_H},
	{"UniJIS-UTF16-V",&pdf_cmap_UniJIS_UTF16_V},
	{"UniJIS-X",&pdf_cmap_UniJIS_X},
	{"UniJIS-X16",&pdf_cmap_UniJIS_X16},
	{"UniKS-UCS2-H",&pdf_cmap_UniKS_UCS2_H},
	{"UniKS-UCS2-V",&pdf_cmap_UniKS_UCS2_V},
	{"UniKS-UTF16-H",&pdf_cmap_UniKS_UTF16_H},
	{"UniKS-UTF16-V",&pdf_cmap_UniKS_UTF16_V},
	{"UniKS-X",&pdf_cmap_UniKS_X},
	{"V",&pdf_cmap_V},
};

#if EXTRA_CMAPS

extern pdf_cmap pdf_cmap_78_EUC_H;
extern pdf_cmap pdf_cmap_78_EUC_V;
extern pdf_cmap pdf_cmap_78_H;
extern pdf_cmap pdf_cmap_78_RKSJ_H;
extern pdf_cmap pdf_cmap_78_RKSJ_V;
extern pdf_cmap pdf_cmap_78_V;
extern pdf_cmap pdf_cmap_78ms_RKSJ_H;
extern pdf_cmap pdf_cmap_78ms_RKSJ_V;
extern pdf_cmap pdf_cmap_90pv_RKSJ_V;
extern pdf_cmap pdf_cmap_Add_H;
extern pdf_cmap pdf_cmap_Add_V;
extern pdf_cmap pdf_cmap_Adobe_CNS1_0;
extern pdf_cmap pdf_cmap_Adobe_CNS1_1;
extern pdf_cmap pdf_cmap_Adobe_CNS1_2;
extern pdf_cmap pdf_cmap_Adobe_CNS1_3;
extern pdf_cmap pdf_cmap_Adobe_CNS1_4;
extern pdf_cmap pdf_cmap_Adobe_CNS1_5;
extern pdf_cmap pdf_cmap_Adobe_CNS1_6;
extern pdf_cmap pdf_cmap_Adobe_GB1_0;
extern pdf_cmap pdf_cmap_Adobe_GB1_1;
extern pdf_cmap pdf_cmap_Adobe_GB1_2;
extern pdf_cmap pdf_cmap_Adobe_GB1_3;
extern pdf_cmap pdf_cmap_Adobe_GB1_4;
extern pdf_cmap pdf_cmap_Adobe_GB1_5;
extern pdf_cmap pdf_cmap_Adobe_Japan1_0;
extern pdf_cmap pdf_cmap_Adobe_Japan1_1;
extern pdf_cmap pdf_cmap_Adobe_Japan1_2;
extern pdf_cmap pdf_cmap_Adobe_Japan1_3;
extern pdf_cmap pdf_cmap_Adobe_Japan1_4;
extern pdf_cmap pdf_cmap_Adobe_Japan1_5;
extern pdf_cmap pdf_cmap_Adobe_Japan1_6;
extern pdf_cmap pdf_cmap_Adobe_Korea1_0;
extern pdf_cmap pdf_cmap_Adobe_Korea1_1;
extern pdf_cmap pdf_cmap_Adobe_Korea1_2;
extern pdf_cmap pdf_cmap_B5_H;
extern pdf_cmap pdf_cmap_B5_V;
extern pdf_cmap pdf_cmap_CNS1_H;
extern pdf_cmap pdf_cmap_CNS1_V;
extern pdf_cmap pdf_cmap_CNS2_H;
extern pdf_cmap pdf_cmap_CNS2_V;
extern pdf_cmap pdf_cmap_ETHK_B5_H;
extern pdf_cmap pdf_cmap_ETHK_B5_V;
extern pdf_cmap pdf_cmap_Ext_H;
extern pdf_cmap pdf_cmap_Ext_V;
extern pdf_cmap pdf_cmap_GBT_EUC_H;
extern pdf_cmap pdf_cmap_GBT_EUC_V;
extern pdf_cmap pdf_cmap_GBT_H;
extern pdf_cmap pdf_cmap_GBT_V;
extern pdf_cmap pdf_cmap_GBTpc_EUC_H;
extern pdf_cmap pdf_cmap_GBTpc_EUC_V;
extern pdf_cmap pdf_cmap_GB_H;
extern pdf_cmap pdf_cmap_GB_V;
extern pdf_cmap pdf_cmap_HKdla_B5_H;
extern pdf_cmap pdf_cmap_HKdla_B5_V;
extern pdf_cmap pdf_cmap_HKdlb_B5_H;
extern pdf_cmap pdf_cmap_HKdlb_B5_V;
extern pdf_cmap pdf_cmap_HKgccs_B5_H;
extern pdf_cmap pdf_cmap_HKgccs_B5_V;
extern pdf_cmap pdf_cmap_HKm314_B5_H;
extern pdf_cmap pdf_cmap_HKm314_B5_V;
extern pdf_cmap pdf_cmap_HKm471_B5_H;
extern pdf_cmap pdf_cmap_HKm471_B5_V;
extern pdf_cmap pdf_cmap_Hankaku;
extern pdf_cmap pdf_cmap_Hiragana;
extern pdf_cmap pdf_cmap_KSC_H;
extern pdf_cmap pdf_cmap_KSC_Johab_H;
extern pdf_cmap pdf_cmap_KSC_Johab_V;
extern pdf_cmap pdf_cmap_KSC_V;
extern pdf_cmap pdf_cmap_KSCpc_EUC_V;
extern pdf_cmap pdf_cmap_Katakana;
extern pdf_cmap pdf_cmap_NWP_H;
extern pdf_cmap pdf_cmap_NWP_V;
extern pdf_cmap pdf_cmap_RKSJ_H;
extern pdf_cmap pdf_cmap_RKSJ_V;
extern pdf_cmap pdf_cmap_Roman;
extern pdf_cmap pdf_cmap_UniJIS2004_UTF16_H;
extern pdf_cmap pdf_cmap_UniJIS2004_UTF16_V;
extern pdf_cmap pdf_cmap_UniJISPro_UCS2_HW_V;
extern pdf_cmap pdf_cmap_UniJISPro_UCS2_V;
extern pdf_cmap pdf_cmap_WP_Symbol;

static const struct table table_extra[] =
{
	{"78-EUC-H",&pdf_cmap_78_EUC_H},
	{"78-EUC-V",&pdf_cmap_78_EUC_V},
	{"78-H",&pdf_cmap_78_H},
	{"78-RKSJ-H",&pdf_cmap_78_RKSJ_H},
	{"78-RKSJ-V",&pdf_cmap_78_RKSJ_V},
	{"78-V",&pdf_cmap_78_V},
	{"78ms-RKSJ-H",&pdf_cmap_78ms_RKSJ_H},
	{"78ms-RKSJ-V",&pdf_cmap_78ms_RKSJ_V},
	{"90pv-RKSJ-V",&pdf_cmap_90pv_RKSJ_V},
	{"Add-H",&pdf_cmap_Add_H},
	{"Add-V",&pdf_cmap_Add_V},
	{"Adobe-CNS1-0",&pdf_cmap_Adobe_CNS1_0},
	{"Adobe-CNS1-1",&pdf_cmap_Adobe_CNS1_1},
	{"Adobe-CNS1-2",&pdf_cmap_Adobe_CNS1_2},
	{"Adobe-CNS1-3",&pdf_cmap_Adobe_CNS1_3},
	{"Adobe-CNS1-4",&pdf_cmap_Adobe_CNS1_4},
	{"Adobe-CNS1-5",&pdf_cmap_Adobe_CNS1_5},
	{"Adobe-CNS1-6",&pdf_cmap_Adobe_CNS1_6},
	{"Adobe-GB1-0",&pdf_cmap_Adobe_GB1_0},
	{"Adobe-GB1-1",&pdf_cmap_Adobe_GB1_1},
	{"Adobe-GB1-2",&pdf_cmap_Adobe_GB1_2},
	{"Adobe-GB1-3",&pdf_cmap_Adobe_GB1_3},
	{"Adobe-GB1-4",&pdf_cmap_Adobe_GB1_4},
	{"Adobe-GB1-5",&pdf_cmap_Adobe_GB1_5},
	{"Adobe-Japan1-0",&pdf_cmap_Adobe_Japan1_0},
	{"Adobe-Japan1-1",&pdf_cmap_Adobe_Japan1_1},
	{"Adobe-Japan1-2",&pdf_cmap_Adobe_Japan1_2},
	{"Adobe-Japan1-3",&pdf_cmap_Adobe_Japan1_3},
	{"Adobe-Japan1-4",&pdf_cmap_Adobe_Japan1_4},
	{"Adobe-Japan1-5",&pdf_cmap_Adobe_Japan1_5},
	{"Adobe-Japan1-6",&pdf_cmap_Adobe_Japan1_6},
	{"Adobe-Korea1-0",&pdf_cmap_Adobe_Korea1_0},
	{"Adobe-Korea1-1",&pdf_cmap_Adobe_Korea1_1},
	{"Adobe-Korea1-2",&pdf_cmap_Adobe_Korea1_2},
	{"B5-H",&pdf_cmap_B5_H},
	{"B5-V",&pdf_cmap_B5_V},
	{"CNS1-H",&pdf_cmap_CNS1_H},
	{"CNS1-V",&pdf_cmap_CNS1_V},
	{"CNS2-H",&pdf_cmap_CNS2_H},
	{"CNS2-V",&pdf_cmap_CNS2_V},
	{"ETHK-B5-H",&pdf_cmap_ETHK_B5_H},
	{"ETHK-B5-V",&pdf_cmap_ETHK_B5_V},
	{"Ext-H",&pdf_cmap_Ext_H},
	{"Ext-V",&pdf_cmap_Ext_V},
	{"GB-H",&pdf_cmap_GB_H},
	{"GB-V",&pdf_cmap_GB_V},
	{"GBT-EUC-H",&pdf_cmap_GBT_EUC_H},
	{"GBT-EUC-V",&pdf_cmap_GBT_EUC_V},
	{"GBT-H",&pdf_cmap_GBT_H},
	{"GBT-V",&pdf_cmap_GBT_V},
	{"GBTpc-EUC-H",&pdf_cmap_GBTpc_EUC_H},
	{"GBTpc-EUC-V",&pdf_cmap_GBTpc_EUC_V},
	{"HKdla-B5-H",&pdf_cmap_HKdla_B5_H},
	{"HKdla-B5-V",&pdf_cmap_HKdla_B5_V},
	{"HKdlb-B5-H",&pdf_cmap_HKdlb_B5_H},
	{"HKdlb-B5-V",&pdf_cmap_HKdlb_B5_V},
	{"HKgccs-B5-H",&pdf_cmap_HKgccs_B5_H},
	{"HKgccs-B5-V",&pdf_cmap_HKgccs_B5_V},
	{"HKm314-B5-H",&pdf_cmap_HKm314_B5_H},
	{"HKm314-B5-V",&pdf_cmap_HKm314_B5_V},
	{"HKm471-B5-H",&pdf_cmap_HKm471_B5_H},
	{"HKm471-B5-V",&pdf_cmap_HKm471_B5_V},
	{"Hankaku",&pdf_cmap_Hankaku},
	{"Hiragana",&pdf_cmap_Hiragana},
	{"KSC-H",&pdf_cmap_KSC_H},
	{"KSC-Johab-H",&pdf_cmap_KSC_Johab_H},
	{"KSC-Johab-V",&pdf_cmap_KSC_Johab_V},
	{"KSC-V",&pdf_cmap_KSC_V},
	{"KSCpc-EUC-V",&pdf_cmap_KSCpc_EUC_V},
	{"Katakana",&pdf_cmap_Katakana},
	{"NWP-H",&pdf_cmap_NWP_H},
	{"NWP-V",&pdf_cmap_NWP_V},
	{"RKSJ-H",&pdf_cmap_RKSJ_H},
	{"RKSJ-V",&pdf_cmap_RKSJ_V},
	{"Roman",&pdf_cmap_Roman},
	{"UniJIS2004-UTF16-H",&pdf_cmap_UniJIS2004_UTF16_H},
	{"UniJIS2004-UTF16-V",&pdf_cmap_UniJIS2004_UTF16_V},
	{"UniJISPro-UCS2-HW-V",&pdf_cmap_UniJISPro_UCS2_HW_V},
	{"UniJISPro-UCS2-V",&pdf_cmap_UniJISPro_UCS2_V},
	{"WP-Symbol",&pdf_cmap_WP_Symbol},
};
#endif

#if UTF8_CMAPS

extern pdf_cmap pdf_cmap_UniCNS_UTF8_H;
extern pdf_cmap pdf_cmap_UniCNS_UTF8_V;
extern pdf_cmap pdf_cmap_UniGB_UTF8_H;
extern pdf_cmap pdf_cmap_UniGB_UTF8_V;
extern pdf_cmap pdf_cmap_UniJIS2004_UTF8_H;
extern pdf_cmap pdf_cmap_UniJIS2004_UTF8_V;
extern pdf_cmap pdf_cmap_UniJISPro_UTF8_V;
extern pdf_cmap pdf_cmap_UniJIS_UTF8_H;
extern pdf_cmap pdf_cmap_UniJIS_UTF8_V;
extern pdf_cmap pdf_cmap_UniJIS_X8;
extern pdf_cmap pdf_cmap_UniKS_UTF8_H;
extern pdf_cmap pdf_cmap_UniKS_UTF8_V;

static const struct table table_utf8[] =
{
	{"UniCNS-UTF8-H",&pdf_cmap_UniCNS_UTF8_H},
	{"UniCNS-UTF8-V",&pdf_cmap_UniCNS_UTF8_V},
	{"UniGB-UTF8-H",&pdf_cmap_UniGB_UTF8_H},
	{"UniGB-UTF8-V",&pdf_cmap_UniGB_UTF8_V},
	{"UniJIS-UTF8-H",&pdf_cmap_UniJIS_UTF8_H},
	{"UniJIS-UTF8-V",&pdf_cmap_UniJIS_UTF8_V},
	{"UniJIS-X8",&pdf_cmap_UniJIS_X8},
	{"UniJIS2004-UTF8-H",&pdf_cmap_UniJIS2004_UTF8_H},
	{"UniJIS2004-UTF8-V",&pdf_cmap_UniJIS2004_UTF8_V},
	{"UniJISPro-UTF8-V",&pdf_cmap_UniJISPro_UTF8_V},
	{"UniKS-UTF8-H",&pdf_cmap_UniKS_UTF8_H},
	{"UniKS-UTF8-V",&pdf_cmap_UniKS_UTF8_V},
};
#endif

#if UTF32_CMAPS

extern pdf_cmap pdf_cmap_UniCNS_UTF32_H;
extern pdf_cmap pdf_cmap_UniCNS_UTF32_V;
extern pdf_cmap pdf_cmap_UniGB_UTF32_H;
extern pdf_cmap pdf_cmap_UniGB_UTF32_V;
extern pdf_cmap pdf_cmap_UniJIS2004_UTF32_H;
extern pdf_cmap pdf_cmap_UniJIS2004_UTF32_V;
extern pdf_cmap pdf_cmap_UniJISX02132004_UTF32_H;
extern pdf_cmap pdf_cmap_UniJISX02132004_UTF32_V;
extern pdf_cmap pdf_cmap_UniJISX0213_UTF32_H;
extern pdf_cmap pdf_cmap_UniJISX0213_UTF32_V;
extern pdf_cmap pdf_cmap_UniJIS_UTF32_H;
extern pdf_cmap pdf_cmap_UniJIS_UTF32_V;
extern pdf_cmap pdf_cmap_UniJIS_X32;
extern pdf_cmap pdf_cmap_UniKS_UTF32_H;
extern pdf_cmap pdf_cmap_UniKS_UTF32_V;

static const struct table table_utf32[] =
{
	{"UniCNS-UTF32-H",&pdf_cmap_UniCNS_UTF32_H},
	{"UniCNS-UTF32-V",&pdf_cmap_UniCNS_UTF32_V},
	{"UniGB-UTF32-H",&pdf_cmap_UniGB_UTF32_H},
	{"UniGB-UTF32-V",&pdf_cmap_UniGB_UTF32_V},
	{"UniJIS-UTF32-H",&pdf_cmap_UniJIS_UTF32_H},
	{"UniJIS-UTF32-V",&pdf_cmap_UniJIS_UTF32_V},
	{"UniJIS-X32",&pdf_cmap_UniJIS_X32},
	{"UniJIS2004-UTF32-H",&pdf_cmap_UniJIS2004_UTF32_H},
	{"UniJIS2004-UTF32-V",&pdf_cmap_UniJIS2004_UTF32_V},
	{"UniJISX0213-UTF32-H",&pdf_cmap_UniJISX0213_UTF32_H},
	{"UniJISX0213-UTF32-V",&pdf_cmap_UniJISX0213_UTF32_V},
	{"UniJISX02132004-UTF32-H",&pdf_cmap_UniJISX02132004_UTF32_H},
	{"UniJISX02132004-UTF32-V",&pdf_cmap_UniJISX02132004_UTF32_V},
	{"UniKS-UTF32-H",&pdf_cmap_UniKS_UTF32_H},
	{"UniKS-UTF32-V",&pdf_cmap_UniKS_UTF32_V},
};
#endif

static pdf_cmap *
pdf_load_builtin_cmap_imp(const struct table *table, int r, const char *name)
{
	int l = 0;
	while (l <= r)
	{
		int m = (l + r) >> 1;
		int c = strcmp(name, table[m].name);
		if (c < 0)
			r = m - 1;
		else if (c > 0)
			l = m + 1;
		else
			return table[m].cmap;
	}
	return NULL;
}

pdf_cmap *
pdf_load_builtin_cmap(fz_context *ctx, const char *name)
{
	pdf_cmap *cmap = NULL;
	if (!cmap) cmap = pdf_load_builtin_cmap_imp(table_cjk, nelem(table_cjk)-1, name);
#if EXTRA_CMAPS
	if (!cmap) cmap = pdf_load_builtin_cmap_imp(table_extra, nelem(table_extra)-1, name);
#endif
#if UTF8_CMAPS
	if (!cmap) cmap = pdf_load_builtin_cmap_imp(table_utf8, nelem(table_utf8)-1, name);
#endif
#if UTF32_CMAPS
	if (!cmap) cmap = pdf_load_builtin_cmap_imp(table_utf32, nelem(table_utf32)-1, name);
#endif
	return cmap;
}

#else

pdf_cmap *
pdf_load_builtin_cmap(fz_context *ctx, const char *name)
{
	return NULL;
}

#endif
