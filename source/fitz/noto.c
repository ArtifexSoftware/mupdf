#include "mupdf/fitz.h"
#include "mupdf/ucdn.h"

#include <string.h>

/*
	Base 14 PDF fonts from URW.
	Noto fonts from Google.
	Source Han Serif from Adobe for CJK.
	DroidSansFallback from Android for CJK.
	Charis SIL from SIL.

	Define TOFU to only include the Base14 and CJK fonts.

	Define TOFU_CJK_LANG to skip Source Han Serif per-language fonts.
	Define TOFU_CJK_EXT to skip DroidSansFallbackFull (and the above).
	Define TOFU_CJK to skip DroidSansFallback (and the above).

	Define TOFU_NOTO to skip ALL non-CJK noto fonts.
	Define TOFU_SYMBOL to skip symbol font.
	Define TOFU_EMOJI to skip emoji/extended symbol font.

	Define TOFU_SIL to skip the SIL fonts (warning: makes EPUB documents ugly).
	Define TOFU_BASE14 to skip the Base 14 fonts (warning: makes PDF unusable).
*/

#ifdef NOTO_SMALL
#define TOFU_CJK_EXT
#define TOFU_SYMBOL
#define TOFU_EMOJI
#define TOFU_SIL
#endif

#ifdef NO_CJK
#define TOFU_CJK
#endif

#ifdef TOFU
#define TOFU_NOTO
#define TOFU_SIL
#endif

#ifdef TOFU_NOTO
#define TOFU_SYMBOL
#define TOFU_EMOJI
#endif

#define RETURN(NAME) \
	do { \
	extern const unsigned char _binary_resources_fonts_##NAME##_start[]; \
	extern const unsigned char _binary_resources_fonts_##NAME##_end; \
	return *size = &_binary_resources_fonts_##NAME##_end - _binary_resources_fonts_##NAME##_start, \
		_binary_resources_fonts_##NAME##_start; \
	} while (0)

const unsigned char *
fz_lookup_base14_font(fz_context *ctx, const char *name, int *size)
{
#ifndef TOFU_BASE14
	if (!strcmp(name, "Courier")) RETURN(urw_NimbusMonoPS_Regular_cff);
	if (!strcmp(name, "Courier-Oblique")) RETURN(urw_NimbusMonoPS_Italic_cff);
	if (!strcmp(name, "Courier-Bold")) RETURN(urw_NimbusMonoPS_Bold_cff);
	if (!strcmp(name, "Courier-BoldOblique")) RETURN(urw_NimbusMonoPS_BoldItalic_cff);
	if (!strcmp(name, "Helvetica")) RETURN(urw_NimbusSans_Regular_cff);
	if (!strcmp(name, "Helvetica-Oblique")) RETURN(urw_NimbusSans_Oblique_cff);
	if (!strcmp(name, "Helvetica-Bold")) RETURN(urw_NimbusSans_Bold_cff);
	if (!strcmp(name, "Helvetica-BoldOblique")) RETURN(urw_NimbusSans_BoldOblique_cff);
	if (!strcmp(name, "Times-Roman")) RETURN(urw_NimbusRoman_Regular_cff);
	if (!strcmp(name, "Times-Italic")) RETURN(urw_NimbusRoman_Italic_cff);
	if (!strcmp(name, "Times-Bold")) RETURN(urw_NimbusRoman_Bold_cff);
	if (!strcmp(name, "Times-BoldItalic")) RETURN(urw_NimbusRoman_BoldItalic_cff);
	if (!strcmp(name, "Symbol")) RETURN(urw_StandardSymbolsPS_cff);
	if (!strcmp(name, "ZapfDingbats")) RETURN(urw_Dingbats_cff);
#endif
	return *size = 0, NULL;
}

#define FAMILY(R, I, B, BI) \
	if (!is_bold) { \
		if (!is_italic) RETURN(R); else RETURN(I); \
	} else { \
		if (!is_italic) RETURN(B); else RETURN(BI); \
	}

const unsigned char *
fz_lookup_builtin_font(fz_context *ctx, const char *name, int is_bold, int is_italic, int *size)
{
#ifndef TOFU_BASE14
	if (!strcmp(name, "Courier")) {
		FAMILY(urw_NimbusMonoPS_Regular_cff,
				urw_NimbusMonoPS_Italic_cff,
				urw_NimbusMonoPS_Bold_cff,
				urw_NimbusMonoPS_BoldItalic_cff)
	}
	if (!strcmp(name, "Helvetica") || !strcmp(name, "Arial")) {
		FAMILY(urw_NimbusSans_Regular_cff,
				urw_NimbusSans_Oblique_cff,
				urw_NimbusSans_Bold_cff,
				urw_NimbusSans_BoldOblique_cff)
	}
	if (!strcmp(name, "Times") || !strcmp(name, "Times Roman") || !strcmp(name, "Times New Roman")) {
		FAMILY(urw_NimbusRoman_Regular_cff,
				urw_NimbusRoman_Italic_cff,
				urw_NimbusRoman_Bold_cff,
				urw_NimbusRoman_BoldItalic_cff)
	}
	if (!strcmp(name, "Dingbats") || !strcmp(name, "Zapf Dingbats")) {
		RETURN(urw_Dingbats_cff);
	}
	if (!strcmp(name, "Symbol")) {
		RETURN(urw_StandardSymbolsPS_cff);
	}
#endif
#ifndef TOFU_SIL
	if (!strcmp(name, "Charis SIL")) {
		FAMILY(sil_CharisSIL_R_cff,
				sil_CharisSIL_I_cff,
				sil_CharisSIL_B_cff,
				sil_CharisSIL_BI_cff)
	}
#endif
#ifndef TOFU_NOTO
	if (!strcmp(name, "Noto Serif")) {
		RETURN(noto_NotoSerif_Regular_otf);
	}
#endif
	return *size = 0, NULL;
}

const unsigned char *
fz_lookup_cjk_font(fz_context *ctx, int ordering, int serif, int *size, int *subfont)
{
	*subfont = 0;
#ifndef TOFU_CJK
#ifndef TOFU_CJK_EXT
#ifndef TOFU_CJK_LANG
	switch (ordering) {
	case FZ_ADOBE_JAPAN_1: *subfont=0; RETURN(han_SourceHanSerif_Regular_ttc);
	case FZ_ADOBE_KOREA_1: *subfont=1; RETURN(han_SourceHanSerif_Regular_ttc);
	case FZ_ADOBE_GB_1: *subfont=2; RETURN(han_SourceHanSerif_Regular_ttc);
	default:
	case FZ_ADOBE_CNS_1: *subfont=3; RETURN(han_SourceHanSerif_Regular_ttc);
	}
#else
	RETURN(droid_DroidSansFallbackFull_ttf);
#endif
#else
	RETURN(droid_DroidSansFallback_ttf);
#endif
#else
	return *size = 0, NULL;
#endif
}

const unsigned char *
fz_lookup_noto_font(fz_context *ctx, int script, int language, int serif, int *size, int *subfont)
{
	/* TODO: Noto(SansSyriacEstrangela); */
	/* TODO: Noto(SansSyriacWestern); */

	*subfont = 0;

	switch (script)
	{
	default:
	case UCDN_SCRIPT_COMMON:
	case UCDN_SCRIPT_INHERITED:
	case UCDN_SCRIPT_UNKNOWN:
		break;

	case UCDN_SCRIPT_HANGUL:
		return fz_lookup_cjk_font(ctx, FZ_ADOBE_KOREA_1, serif, size, subfont);
	case UCDN_SCRIPT_HIRAGANA:
	case UCDN_SCRIPT_KATAKANA:
		return fz_lookup_cjk_font(ctx, FZ_ADOBE_JAPAN_1, serif, size, subfont);
	case UCDN_SCRIPT_BOPOMOFO:
		return fz_lookup_cjk_font(ctx, FZ_ADOBE_CNS_1, serif, size, subfont);
	case UCDN_SCRIPT_HAN:
		switch (language)
		{
		case FZ_LANG_ja: return fz_lookup_cjk_font(ctx, FZ_ADOBE_JAPAN_1, serif, size, subfont);
		case FZ_LANG_ko: return fz_lookup_cjk_font(ctx, FZ_ADOBE_KOREA_1, serif, size, subfont);
		case FZ_LANG_zh_Hans: return fz_lookup_cjk_font(ctx, FZ_ADOBE_GB_1, serif, size, subfont);
		default:
		case FZ_LANG_zh_Hant: return fz_lookup_cjk_font(ctx, FZ_ADOBE_CNS_1, serif, size, subfont);
		}

	case UCDN_SCRIPT_BRAILLE: break; /* no dedicated font; fallback to NotoSansSymbols will cover this */

#ifndef TOFU_NOTO
	case UCDN_SCRIPT_LATIN:
	case UCDN_SCRIPT_GREEK:
	case UCDN_SCRIPT_CYRILLIC:
		RETURN(noto_NotoSerif_Regular_otf);
		break;

	case UCDN_SCRIPT_ARABIC:
		if (language == FZ_LANG_ur || language == FZ_LANG_urd)
			RETURN(noto_NotoNastaliqUrdu_Regular_ttf);
		RETURN(noto_NotoNaskhArabic_Regular_ttf);

	case UCDN_SCRIPT_SYRIAC:
		/* TODO: RETURN(noto_NotoSansSyriacEastern_Regular_ttf); */
		/* TODO: RETURN(noto_NotoSansSyriacWestern_Regular_ttf); */
		/* TODO: RETURN(noto_NotoSansSyriacEstrangela_Regular_ttf); */
		RETURN(noto_NotoSansSyriacWestern_Regular_ttf);

	case UCDN_SCRIPT_MEROITIC_CURSIVE:
	case UCDN_SCRIPT_MEROITIC_HIEROGLYPHS:
		RETURN(noto_NotoSansMeroitic_Regular_otf);

	case UCDN_SCRIPT_ADLAM: RETURN(noto_NotoSansAdlam_Regular_otf);
	case UCDN_SCRIPT_AHOM: RETURN(noto_NotoSansAhom_Regular_otf);
	case UCDN_SCRIPT_ANATOLIAN_HIEROGLYPHS: RETURN(noto_NotoSansAnatolianHieroglyphs_Regular_otf);
	case UCDN_SCRIPT_ARMENIAN: RETURN(noto_NotoSerifArmenian_Regular_otf);
	case UCDN_SCRIPT_AVESTAN: RETURN(noto_NotoSansAvestan_Regular_otf);
	case UCDN_SCRIPT_BALINESE: RETURN(noto_NotoSerifBalinese_Regular_otf);
	case UCDN_SCRIPT_BAMUM: RETURN(noto_NotoSansBamum_Regular_otf);
	case UCDN_SCRIPT_BASSA_VAH: RETURN(noto_NotoSansBassaVah_Regular_otf);
	case UCDN_SCRIPT_BATAK: RETURN(noto_NotoSansBatak_Regular_otf);
	case UCDN_SCRIPT_BENGALI: RETURN(noto_NotoSansBengali_Regular_otf);
	case UCDN_SCRIPT_BHAIKSUKI: RETURN(noto_NotoSansBhaiksuki_Regular_otf);
	case UCDN_SCRIPT_BRAHMI: RETURN(noto_NotoSansBrahmi_Regular_otf);
	case UCDN_SCRIPT_BUGINESE: RETURN(noto_NotoSansBuginese_Regular_otf);
	case UCDN_SCRIPT_BUHID: RETURN(noto_NotoSansBuhid_Regular_otf);
	case UCDN_SCRIPT_CANADIAN_ABORIGINAL: RETURN(noto_NotoSansCanadianAboriginal_Regular_otf);
	case UCDN_SCRIPT_CARIAN: RETURN(noto_NotoSansCarian_Regular_otf);
	case UCDN_SCRIPT_CAUCASIAN_ALBANIAN: break;
	case UCDN_SCRIPT_CHAKMA: RETURN(noto_NotoSansChakma_Regular_otf);
	case UCDN_SCRIPT_CHAM: RETURN(noto_NotoSansCham_Regular_otf);
	case UCDN_SCRIPT_CHEROKEE: RETURN(noto_NotoSansCherokee_Regular_otf);
	case UCDN_SCRIPT_COPTIC: RETURN(noto_NotoSansCoptic_Regular_otf);
	case UCDN_SCRIPT_CUNEIFORM: RETURN(noto_NotoSansCuneiform_Regular_otf);
	case UCDN_SCRIPT_CYPRIOT: RETURN(noto_NotoSansCypriot_Regular_otf);
	case UCDN_SCRIPT_DESERET: RETURN(noto_NotoSansDeseret_Regular_otf);
	case UCDN_SCRIPT_DEVANAGARI: RETURN(noto_NotoSansDevanagari_Regular_otf);
	case UCDN_SCRIPT_DUPLOYAN: break;
	case UCDN_SCRIPT_EGYPTIAN_HIEROGLYPHS: RETURN(noto_NotoSansEgyptianHieroglyphs_Regular_otf);
	case UCDN_SCRIPT_ELBASAN: RETURN(noto_NotoSansElbasan_Regular_otf);
	case UCDN_SCRIPT_ETHIOPIC: RETURN(noto_NotoSerifEthiopic_Regular_otf);
	case UCDN_SCRIPT_GEORGIAN: RETURN(noto_NotoSerifGeorgian_Regular_otf);
	case UCDN_SCRIPT_GLAGOLITIC: RETURN(noto_NotoSansGlagolitic_Regular_otf);
	case UCDN_SCRIPT_GOTHIC: RETURN(noto_NotoSansGothic_Regular_otf);
	case UCDN_SCRIPT_GRANTHA: break;
	case UCDN_SCRIPT_GUJARATI: RETURN(noto_NotoSerifGujarati_Regular_otf);
	case UCDN_SCRIPT_GURMUKHI: RETURN(noto_NotoSerifGurmukhi_Regular_otf);
	case UCDN_SCRIPT_HANUNOO: RETURN(noto_NotoSansHanunoo_Regular_otf);
	case UCDN_SCRIPT_HATRAN: RETURN(noto_NotoSansHatran_Regular_otf);
	case UCDN_SCRIPT_HEBREW: RETURN(noto_NotoSerifHebrew_Regular_otf);
	case UCDN_SCRIPT_IMPERIAL_ARAMAIC: RETURN(noto_NotoSansImperialAramaic_Regular_otf);
	case UCDN_SCRIPT_INSCRIPTIONAL_PAHLAVI: RETURN(noto_NotoSansInscriptionalPahlavi_Regular_otf);
	case UCDN_SCRIPT_INSCRIPTIONAL_PARTHIAN: RETURN(noto_NotoSansInscriptionalParthian_Regular_otf);
	case UCDN_SCRIPT_JAVANESE: RETURN(noto_NotoSansJavanese_Regular_ttf);
	case UCDN_SCRIPT_KAITHI: RETURN(noto_NotoSansKaithi_Regular_otf);
	case UCDN_SCRIPT_KANNADA: RETURN(noto_NotoSerifKannada_Regular_otf);
	case UCDN_SCRIPT_KAYAH_LI: RETURN(noto_NotoSansKayahLi_Regular_otf);
	case UCDN_SCRIPT_KHAROSHTHI: RETURN(noto_NotoSansKharoshthi_Regular_otf);
	case UCDN_SCRIPT_KHMER: RETURN(noto_NotoSerifKhmer_Regular_otf);
	case UCDN_SCRIPT_KHOJKI: break;
	case UCDN_SCRIPT_KHUDAWADI: break;
	case UCDN_SCRIPT_LAO: RETURN(noto_NotoSerifLao_Regular_otf);
	case UCDN_SCRIPT_LEPCHA: RETURN(noto_NotoSansLepcha_Regular_otf);
	case UCDN_SCRIPT_LIMBU: RETURN(noto_NotoSansLimbu_Regular_otf);
	case UCDN_SCRIPT_LINEAR_A: RETURN(noto_NotoSansLinearA_Regular_otf);
	case UCDN_SCRIPT_LINEAR_B: RETURN(noto_NotoSansLinearB_Regular_otf);
	case UCDN_SCRIPT_LISU: RETURN(noto_NotoSansLisu_Regular_otf);
	case UCDN_SCRIPT_LYCIAN: RETURN(noto_NotoSansLycian_Regular_otf);
	case UCDN_SCRIPT_LYDIAN: RETURN(noto_NotoSansLydian_Regular_otf);
	case UCDN_SCRIPT_MAHAJANI: break;
	case UCDN_SCRIPT_MALAYALAM: RETURN(noto_NotoSansMalayalam_Regular_otf);
	case UCDN_SCRIPT_MANDAIC: RETURN(noto_NotoSansMandaic_Regular_otf);
	case UCDN_SCRIPT_MANICHAEAN: RETURN(noto_NotoSansManichaean_Regular_otf);
	case UCDN_SCRIPT_MARCHEN: RETURN(noto_NotoSansMarchen_Regular_otf);
	case UCDN_SCRIPT_MASARAM_GONDI: break;
	case UCDN_SCRIPT_MEETEI_MAYEK: RETURN(noto_NotoSansMeeteiMayek_Regular_otf);
	case UCDN_SCRIPT_MENDE_KIKAKUI: RETURN(noto_NotoSansMendeKikakui_Regular_otf);
	case UCDN_SCRIPT_MIAO: RETURN(noto_NotoSansMiao_Regular_otf);
	case UCDN_SCRIPT_MODI: break;
	case UCDN_SCRIPT_MONGOLIAN: RETURN(noto_NotoSansMongolian_Regular_ttf);
	case UCDN_SCRIPT_MRO: RETURN(noto_NotoSansMro_Regular_otf);
	case UCDN_SCRIPT_MULTANI: RETURN(noto_NotoSansMultani_Regular_otf);
	case UCDN_SCRIPT_MYANMAR: RETURN(noto_NotoSerifMyanmar_Regular_otf);
	case UCDN_SCRIPT_NABATAEAN: RETURN(noto_NotoSansNabataean_Regular_otf);
	case UCDN_SCRIPT_NEWA: RETURN(noto_NotoSansNewa_Regular_otf);
	case UCDN_SCRIPT_NEW_TAI_LUE: RETURN(noto_NotoSansNewTaiLue_Regular_otf);
	case UCDN_SCRIPT_NKO: RETURN(noto_NotoSansNKo_Regular_otf);
	case UCDN_SCRIPT_NUSHU: break;
	case UCDN_SCRIPT_OGHAM: RETURN(noto_NotoSansOgham_Regular_otf);
	case UCDN_SCRIPT_OLD_HUNGARIAN: break;
	case UCDN_SCRIPT_OLD_ITALIC: RETURN(noto_NotoSansOldItalic_Regular_otf);
	case UCDN_SCRIPT_OLD_NORTH_ARABIAN: RETURN(noto_NotoSansOldNorthArabian_Regular_otf);
	case UCDN_SCRIPT_OLD_PERMIC: RETURN(noto_NotoSansOldPermic_Regular_otf);
	case UCDN_SCRIPT_OLD_PERSIAN: RETURN(noto_NotoSansOldPersian_Regular_otf);
	case UCDN_SCRIPT_OLD_SOUTH_ARABIAN: RETURN(noto_NotoSansOldSouthArabian_Regular_otf);
	case UCDN_SCRIPT_OLD_TURKIC: RETURN(noto_NotoSansOldTurkic_Regular_otf);
	case UCDN_SCRIPT_OL_CHIKI: RETURN(noto_NotoSansOlChiki_Regular_otf);
	case UCDN_SCRIPT_ORIYA: RETURN(noto_NotoSansOriya_Regular_ttf);
	case UCDN_SCRIPT_OSAGE: RETURN(noto_NotoSansOsage_Regular_otf);
	case UCDN_SCRIPT_OSMANYA: RETURN(noto_NotoSansOsmanya_Regular_otf);
	case UCDN_SCRIPT_PAHAWH_HMONG: RETURN(noto_NotoSansPahawhHmong_Regular_otf);
	case UCDN_SCRIPT_PALMYRENE: RETURN(noto_NotoSansPalmyrene_Regular_otf);
	case UCDN_SCRIPT_PAU_CIN_HAU: RETURN(noto_NotoSansPauCinHau_Regular_otf);
	case UCDN_SCRIPT_PHAGS_PA: RETURN(noto_NotoSansPhagsPa_Regular_otf);
	case UCDN_SCRIPT_PHOENICIAN: RETURN(noto_NotoSansPhoenician_Regular_otf);
	case UCDN_SCRIPT_PSALTER_PAHLAVI: break;
	case UCDN_SCRIPT_REJANG: RETURN(noto_NotoSansRejang_Regular_otf);
	case UCDN_SCRIPT_RUNIC: RETURN(noto_NotoSansRunic_Regular_otf);
	case UCDN_SCRIPT_SAMARITAN: RETURN(noto_NotoSansSamaritan_Regular_otf);
	case UCDN_SCRIPT_SAURASHTRA: RETURN(noto_NotoSansSaurashtra_Regular_otf);
	case UCDN_SCRIPT_SHARADA: RETURN(noto_NotoSansSharada_Regular_otf);
	case UCDN_SCRIPT_SHAVIAN: RETURN(noto_NotoSansShavian_Regular_otf);
	case UCDN_SCRIPT_SIDDHAM: break;
	case UCDN_SCRIPT_SIGNWRITING: break;
	case UCDN_SCRIPT_SINHALA: RETURN(noto_NotoSerifSinhala_Regular_otf);
	case UCDN_SCRIPT_SORA_SOMPENG: RETURN(noto_NotoSansSoraSompeng_Regular_otf);
	case UCDN_SCRIPT_SOYOMBO: break;
	case UCDN_SCRIPT_SUNDANESE: RETURN(noto_NotoSansSundanese_Regular_otf);
	case UCDN_SCRIPT_SYLOTI_NAGRI: RETURN(noto_NotoSansSylotiNagri_Regular_otf);
	case UCDN_SCRIPT_TAGALOG: RETURN(noto_NotoSansTagalog_Regular_otf);
	case UCDN_SCRIPT_TAGBANWA: RETURN(noto_NotoSansTagbanwa_Regular_otf);
	case UCDN_SCRIPT_TAI_LE: RETURN(noto_NotoSansTaiLe_Regular_otf);
	case UCDN_SCRIPT_TAI_THAM: RETURN(noto_NotoSansTaiTham_Regular_ttf);
	case UCDN_SCRIPT_TAI_VIET: RETURN(noto_NotoSansTaiViet_Regular_otf);
	case UCDN_SCRIPT_TAKRI: break;
	case UCDN_SCRIPT_TAMIL: RETURN(noto_NotoSerifTamil_Regular_otf);
	case UCDN_SCRIPT_TANGUT: break;
	case UCDN_SCRIPT_TELUGU: RETURN(noto_NotoSerifTelugu_Regular_ttf);
	case UCDN_SCRIPT_THAANA: RETURN(noto_NotoSansThaana_Regular_ttf);
	case UCDN_SCRIPT_THAI: RETURN(noto_NotoSerifThai_Regular_otf);
	case UCDN_SCRIPT_TIBETAN: RETURN(noto_NotoSansTibetan_Regular_ttf);
	case UCDN_SCRIPT_TIFINAGH: RETURN(noto_NotoSansTifinagh_Regular_otf);
	case UCDN_SCRIPT_TIRHUTA: break;
	case UCDN_SCRIPT_UGARITIC: RETURN(noto_NotoSansUgaritic_Regular_otf);
	case UCDN_SCRIPT_VAI: RETURN(noto_NotoSansVai_Regular_otf);
	case UCDN_SCRIPT_WARANG_CITI: break;
	case UCDN_SCRIPT_YI: RETURN(noto_NotoSansYi_Regular_otf);
	case UCDN_SCRIPT_ZANABAZAR_SQUARE: break;

#endif /* TOFU_NOTO */
	}

	return *size = 0, NULL;
}

const unsigned char *
fz_lookup_noto_symbol_font(fz_context *ctx, int *size)
{
#ifndef TOFU_SYMBOL
	RETURN(noto_NotoSansSymbols_Regular_otf);
#else
	return *size = 0, NULL;
#endif
}

const unsigned char *
fz_lookup_noto_emoji_font(fz_context *ctx, int *size)
{
#ifndef TOFU_EMOJI
	RETURN(noto_NotoSansSymbols2_Regular_otf);
#else
	return *size = 0, NULL;
#endif
}
