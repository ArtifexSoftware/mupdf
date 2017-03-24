#include "mupdf/fitz.h"
#include "mupdf/ucdn.h"

#include <string.h>

/*
	Base 14 PDF fonts from URW.
	Noto fonts from Google.
	Source Han Sans from Adobe for CJK.
	DroidSansFallback from Android for CJK.
	Charis SIL from SIL.

	Define TOFU to only include the Base14 and CJK fonts.

	Define TOFU_CJK_LANG to skip Source Han Sans per-language fonts.
	Define TOFU_CJK_EXT to skip DroidSansFallbackFull (and the above).
	Define TOFU_CJK to skip DroidSansFallback (and the above).

	Define TOFU_NOTO to skip ALL non-CJK noto fonts.
	Define TOFU_EMOJI to skip emoji font.
	Define TOFU_HISTORIC to skip ancient/historic scripts.
	Define TOFU_SYMBOL to skip symbol font.

	Define TOFU_SIL to skip the SIL fonts (warning: makes EPUB documents ugly).
	Define TOFU_BASE14 to skip the Base 14 fonts (warning: makes PDF unusable).
*/

#ifdef NOTO_SMALL
#define TOFU_CJK_EXT
#define TOFU_EMOJI
#define TOFU_HISTORIC
#define TOFU_SYMBOL
#define TOFU_SIL
#endif

#ifdef NOCJK
#define TOFU_CJK
#endif

#ifdef TOFU
#define TOFU_NOTO
#define TOFU_SIL
#endif

#ifdef TOFU_NOTO
#define TOFU_EMOJI
#define TOFU_HISTORIC
#define TOFU_SYMBOL
#endif

#define RETURN(NAME) \
	do { \
	extern const int fz_resources_fonts_ ## NAME ## _size; \
	extern const char fz_resources_fonts_ ## NAME []; \
	return *size = fz_resources_fonts_ ## NAME ## _size, fz_resources_fonts_ ## NAME; \
	} while (0)

const char *
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

const char *
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
		RETURN(noto_NotoSerif_Regular_ttf);
	}
	if (!strcmp(name, "Noto Sans")) {
		RETURN(noto_NotoSans_Regular_ttf);
	}
#endif
#ifndef TOFU_EMOJI
	if (!strcmp(name, "Emoji") || !strcmp(name, "Noto Emoji")) {
		RETURN(noto_NotoEmoji_Regular_ttf);
	}
#endif
	return *size = 0, NULL;
}

const char *
fz_lookup_cjk_font(fz_context *ctx, int registry, int serif, int wmode, int *size, int *index)
{
	if (index) *index = 0;
#ifndef TOFU_CJK
#ifndef TOFU_CJK_EXT
#ifndef TOFU_CJK_LANG
	switch (registry) {
	case FZ_ADOBE_JAPAN_1: RETURN(han_SourceHanSansJP_Regular_otf);
	case FZ_ADOBE_KOREA_1: RETURN(han_SourceHanSansKR_Regular_otf);
	default:
	case FZ_ADOBE_GB_1: RETURN(han_SourceHanSansCN_Regular_otf);
	case FZ_ADOBE_CNS_1: RETURN(han_SourceHanSansTW_Regular_otf);
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

#define Noto(SANS) RETURN(noto_Noto ## SANS ## _Regular_ttf)

#define Noto2(SANS,SERIF) \
	if (serif) { RETURN(noto_Noto ## SERIF ## _Regular_ttf); } else { RETURN(noto_Noto ## SANS ## _Regular_ttf); }

const char *
fz_lookup_noto_font(fz_context *ctx, int script, int language, int serif, int *size)
{
	/* TODO: Noto(SansSyriacEstrangela); */
	/* TODO: Noto(SansSyriacWestern); */

	switch (script)
	{
	default:
	case UCDN_SCRIPT_COMMON:
	case UCDN_SCRIPT_INHERITED:
	case UCDN_SCRIPT_UNKNOWN:
		break;

	case UCDN_SCRIPT_HANGUL:
		return fz_lookup_cjk_font(ctx, FZ_ADOBE_KOREA_1, serif, 0, size, NULL);
	case UCDN_SCRIPT_HIRAGANA:
	case UCDN_SCRIPT_KATAKANA:
		return fz_lookup_cjk_font(ctx, FZ_ADOBE_JAPAN_1, serif, 0, size, NULL);
	case UCDN_SCRIPT_BOPOMOFO:
		return fz_lookup_cjk_font(ctx, FZ_ADOBE_GB_1, serif, 0, size, NULL);
	case UCDN_SCRIPT_HAN:
		switch (language)
		{
		case FZ_LANG_ja: return fz_lookup_cjk_font(ctx, FZ_ADOBE_JAPAN_1, serif, 0, size, NULL);
		case FZ_LANG_ko: return fz_lookup_cjk_font(ctx, FZ_ADOBE_KOREA_1, serif, 0, size, NULL);
		case FZ_LANG_zh_Hant: return fz_lookup_cjk_font(ctx, FZ_ADOBE_CNS_1, serif, 0, size, NULL);
		default:
		case FZ_LANG_zh_Hans: return fz_lookup_cjk_font(ctx, FZ_ADOBE_GB_1, serif, 0, size, NULL);
		}

#ifndef TOFU_NOTO
	case UCDN_SCRIPT_LATIN: Noto2(Sans, Serif);
	case UCDN_SCRIPT_GREEK: Noto2(Sans, Serif);
	case UCDN_SCRIPT_CYRILLIC: Noto2(Sans, Serif);

	case UCDN_SCRIPT_ARABIC:
		if (language == FZ_LANG_ur || language == FZ_LANG_urd)
			Noto(NastaliqUrdu);
		Noto2(KufiArabic, NaskhArabic);

	case UCDN_SCRIPT_ARMENIAN: Noto2(SansArmenian, SerifArmenian);
	case UCDN_SCRIPT_BALINESE: Noto(SansBalinese);
	case UCDN_SCRIPT_BAMUM: Noto(SansBamum);
	case UCDN_SCRIPT_BATAK: Noto(SansBatak);
	case UCDN_SCRIPT_BENGALI: Noto2(SansBengali, SerifBengali);
	case UCDN_SCRIPT_CANADIAN_ABORIGINAL: Noto(SansCanadianAboriginal);
	case UCDN_SCRIPT_CHAM: Noto(SansCham);
	case UCDN_SCRIPT_CHEROKEE: Noto(SansCherokee);
	case UCDN_SCRIPT_DEVANAGARI: Noto2(SansDevanagari, SerifDevanagari);
	case UCDN_SCRIPT_ETHIOPIC: Noto(SansEthiopic);
	case UCDN_SCRIPT_GEORGIAN: Noto2(SansGeorgian, SerifGeorgian);
	case UCDN_SCRIPT_GUJARATI: Noto2(SansGujarati, SerifGujarati);
	case UCDN_SCRIPT_GURMUKHI: Noto(SansGurmukhi);
	case UCDN_SCRIPT_HEBREW: Noto(SansHebrew);
	case UCDN_SCRIPT_JAVANESE: Noto(SansJavanese);
	case UCDN_SCRIPT_KANNADA: Noto2(SansKannada, SerifKannada);
	case UCDN_SCRIPT_KAYAH_LI: Noto(SansKayahLi);
	case UCDN_SCRIPT_KHMER: Noto2(SansKhmer, SerifKhmer);
	case UCDN_SCRIPT_LAO: Noto2(SansLao, SerifLao);
	case UCDN_SCRIPT_LEPCHA: Noto(SansLepcha);
	case UCDN_SCRIPT_LIMBU: Noto(SansLimbu);
	case UCDN_SCRIPT_LISU: Noto(SansLisu);
	case UCDN_SCRIPT_MALAYALAM: Noto2(SansMalayalam, SerifMalayalam);
	case UCDN_SCRIPT_MANDAIC: Noto(SansMandaic);
	case UCDN_SCRIPT_MEETEI_MAYEK: Noto(SansMeeteiMayek);
	case UCDN_SCRIPT_MONGOLIAN: Noto(SansMongolian);
	case UCDN_SCRIPT_MYANMAR: Noto(SansMyanmar);
	case UCDN_SCRIPT_NEW_TAI_LUE: Noto(SansNewTaiLue);
	case UCDN_SCRIPT_NKO: Noto(SansNKo);
	case UCDN_SCRIPT_OL_CHIKI: Noto(SansOlChiki);
	case UCDN_SCRIPT_ORIYA: Noto(SansOriya);
	case UCDN_SCRIPT_SAURASHTRA: Noto(SansSaurashtra);
	case UCDN_SCRIPT_SINHALA: Noto(SansSinhala);
	case UCDN_SCRIPT_SUNDANESE: Noto(SansSundanese);
	case UCDN_SCRIPT_SYLOTI_NAGRI: Noto(SansSylotiNagri);
	case UCDN_SCRIPT_SYRIAC: Noto(SansSyriacEastern);
	case UCDN_SCRIPT_TAI_LE: Noto(SansTaiLe);
	case UCDN_SCRIPT_TAI_THAM: Noto(SansTaiTham);
	case UCDN_SCRIPT_TAI_VIET: Noto(SansTaiViet);
	case UCDN_SCRIPT_TAMIL: Noto2(SansTamil, SerifTamil);
	case UCDN_SCRIPT_TELUGU: Noto2(SansTelugu, SerifTelugu);
	case UCDN_SCRIPT_THAANA: Noto(SansThaana);
	case UCDN_SCRIPT_THAI: Noto2(SansThai, SerifThai);
	case UCDN_SCRIPT_TIBETAN: Noto(SansTibetan);
	case UCDN_SCRIPT_TIFINAGH: Noto(SansTifinagh);
	case UCDN_SCRIPT_VAI: Noto(SansVai);
	case UCDN_SCRIPT_YI: Noto(SansYi);

#ifndef TOFU_HISTORIC
	case UCDN_SCRIPT_AVESTAN: Noto(SansAvestan);
	case UCDN_SCRIPT_BRAHMI: Noto(SansBrahmi);
	case UCDN_SCRIPT_BUGINESE: Noto(SansBuginese);
	case UCDN_SCRIPT_BUHID: Noto(SansBuhid);
	case UCDN_SCRIPT_CARIAN: Noto(SansCarian);
	case UCDN_SCRIPT_COPTIC: Noto(SansCoptic);
	case UCDN_SCRIPT_CUNEIFORM: Noto(SansCuneiform);
	case UCDN_SCRIPT_CYPRIOT: Noto(SansCypriot);
	case UCDN_SCRIPT_DESERET: Noto(SansDeseret);
	case UCDN_SCRIPT_EGYPTIAN_HIEROGLYPHS: Noto(SansEgyptianHieroglyphs);
	case UCDN_SCRIPT_GLAGOLITIC: Noto(SansGlagolitic);
	case UCDN_SCRIPT_GOTHIC: Noto(SansGothic);
	case UCDN_SCRIPT_HANUNOO: Noto(SansHanunoo);
	case UCDN_SCRIPT_IMPERIAL_ARAMAIC: Noto(SansImperialAramaic);
	case UCDN_SCRIPT_INSCRIPTIONAL_PAHLAVI: Noto(SansInscriptionalPahlavi);
	case UCDN_SCRIPT_INSCRIPTIONAL_PARTHIAN: Noto(SansInscriptionalParthian);
	case UCDN_SCRIPT_KAITHI: Noto(SansKaithi);
	case UCDN_SCRIPT_KHAROSHTHI: Noto(SansKharoshthi);
	case UCDN_SCRIPT_LINEAR_B: Noto(SansLinearB);
	case UCDN_SCRIPT_LYCIAN: Noto(SansLycian);
	case UCDN_SCRIPT_LYDIAN: Noto(SansLydian);
	case UCDN_SCRIPT_OGHAM: Noto(SansOgham);
	case UCDN_SCRIPT_OLD_ITALIC: Noto(SansOldItalic);
	case UCDN_SCRIPT_OLD_PERSIAN: Noto(SansOldPersian);
	case UCDN_SCRIPT_OLD_SOUTH_ARABIAN: Noto(SansOldSouthArabian);
	case UCDN_SCRIPT_OLD_TURKIC: Noto(SansOldTurkic);
	case UCDN_SCRIPT_OSMANYA: Noto(SansOsmanya);
	case UCDN_SCRIPT_PHAGS_PA: Noto(SansPhagsPa);
	case UCDN_SCRIPT_PHOENICIAN: Noto(SansPhoenician);
	case UCDN_SCRIPT_REJANG: Noto(SansRejang);
	case UCDN_SCRIPT_RUNIC: Noto(SansRunic);
	case UCDN_SCRIPT_SAMARITAN: Noto(SansSamaritan);
	case UCDN_SCRIPT_SHAVIAN: Noto(SansShavian);
	case UCDN_SCRIPT_TAGALOG: Noto(SansTagalog);
	case UCDN_SCRIPT_TAGBANWA: Noto(SansTagbanwa);
	case UCDN_SCRIPT_UGARITIC: Noto(SansUgaritic);
#endif

	/* No fonts available for these scripts: */
	case UCDN_SCRIPT_ADLAM: break;
	case UCDN_SCRIPT_BRAILLE: break; /* no dedicated font; fallback to NotoSansSymbols will cover this */
	case UCDN_SCRIPT_CHAKMA: break;
	case UCDN_SCRIPT_MIAO: break;
	case UCDN_SCRIPT_NEWA: break;
#ifndef TOFU_HISTORIC
	case UCDN_SCRIPT_AHOM: break;
	case UCDN_SCRIPT_ANATOLIAN_HIEROGLYPHS: break;
	case UCDN_SCRIPT_BASSA_VAH: break;
	case UCDN_SCRIPT_BHAIKSUKI: break;
	case UCDN_SCRIPT_CAUCASIAN_ALBANIAN: break;
	case UCDN_SCRIPT_DUPLOYAN: break;
	case UCDN_SCRIPT_ELBASAN: break;
	case UCDN_SCRIPT_GRANTHA: break;
	case UCDN_SCRIPT_HATRAN: break;
	case UCDN_SCRIPT_KHOJKI: break;
	case UCDN_SCRIPT_KHUDAWADI: break;
	case UCDN_SCRIPT_LINEAR_A: break;
	case UCDN_SCRIPT_MAHAJANI: break;
	case UCDN_SCRIPT_MANICHAEAN: break;
	case UCDN_SCRIPT_MARCHEN: break;
	case UCDN_SCRIPT_MENDE_KIKAKUI: break;
	case UCDN_SCRIPT_MEROITIC_CURSIVE: break;
	case UCDN_SCRIPT_MEROITIC_HIEROGLYPHS: break;
	case UCDN_SCRIPT_MODI: break;
	case UCDN_SCRIPT_MRO: break;
	case UCDN_SCRIPT_MULTANI: break;
	case UCDN_SCRIPT_NABATAEAN: break;
	case UCDN_SCRIPT_OLD_HUNGARIAN: break;
	case UCDN_SCRIPT_OLD_NORTH_ARABIAN: break;
	case UCDN_SCRIPT_OLD_PERMIC: break;
	case UCDN_SCRIPT_OSAGE: break;
	case UCDN_SCRIPT_PAHAWH_HMONG: break;
	case UCDN_SCRIPT_PALMYRENE: break;
	case UCDN_SCRIPT_PAU_CIN_HAU: break;
	case UCDN_SCRIPT_PSALTER_PAHLAVI: break;
	case UCDN_SCRIPT_SHARADA: break;
	case UCDN_SCRIPT_SIDDHAM: break;
	case UCDN_SCRIPT_SIGNWRITING: break;
	case UCDN_SCRIPT_SORA_SOMPENG: break;
	case UCDN_SCRIPT_TAKRI: break;
	case UCDN_SCRIPT_TANGUT: break;
	case UCDN_SCRIPT_TIRHUTA: break;
	case UCDN_SCRIPT_WARANG_CITI: break;
#endif

#endif
	}

	return *size = 0, NULL;
}

const char *
fz_lookup_noto_symbol_font(fz_context *ctx, int *size)
{
#ifndef TOFU_SYMBOL
	RETURN(noto_NotoSansSymbols_Regular_ttf);
#else
	return *size = 0, NULL;
#endif
}

const char *
fz_lookup_noto_emoji_font(fz_context *ctx, int *size)
{
#ifndef TOFU_EMOJI
	RETURN(noto_NotoEmoji_Regular_ttf);
#else
	return *size = 0, NULL;
#endif
}
