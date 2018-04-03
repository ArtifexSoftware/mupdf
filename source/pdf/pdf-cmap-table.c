#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

#include <string.h>

#ifdef NOCJK

pdf_cmap *
pdf_load_builtin_cmap(fz_context *ctx, const char *name)
{
	if (!strcmp(name, "Identity-H")) return pdf_new_identity_cmap(ctx, 0, 2);
	if (!strcmp(name, "Identity-V")) return pdf_new_identity_cmap(ctx, 1, 2);
	return NULL;
}

#else

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
extern pdf_cmap pdf_cmap_Identity_H;
extern pdf_cmap pdf_cmap_Identity_V;
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
extern pdf_cmap pdf_cmap_UniJIS_X;
extern pdf_cmap pdf_cmap_UniKS_UCS2_H;
extern pdf_cmap pdf_cmap_UniKS_UCS2_V;
extern pdf_cmap pdf_cmap_UniKS_UTF16_H;
extern pdf_cmap pdf_cmap_UniKS_UTF16_V;
extern pdf_cmap pdf_cmap_UniKS_X;
extern pdf_cmap pdf_cmap_V;

const struct { const char *name; pdf_cmap *cmap; } table[] = {
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
	{"Identity-H",&pdf_cmap_Identity_H},
	{"Identity-V",&pdf_cmap_Identity_V},
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
	{"UniKS-UCS2-H",&pdf_cmap_UniKS_UCS2_H},
	{"UniKS-UCS2-V",&pdf_cmap_UniKS_UCS2_V},
	{"UniKS-UTF16-H",&pdf_cmap_UniKS_UTF16_H},
	{"UniKS-UTF16-V",&pdf_cmap_UniKS_UTF16_V},
	{"UniKS-X",&pdf_cmap_UniKS_X},
	{"V",&pdf_cmap_V},
};

pdf_cmap *
pdf_load_builtin_cmap(fz_context *ctx, const char *name)
{
	int r = nelem(table)-1;
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

#endif
