@echo off

if not exist scripts/fontdump.c cd ../..
if not exist scripts/fontdump.c goto usage
if not exist generated mkdir generated

cl /nologo -Iinclude scripts/namedump.c

if not exist namedump.exe goto usage

if not exist include/mupdf/pdf/name-table.h namedump.exe resources/pdf/names.txt include/mupdf/pdf/name-table.h source/pdf/pdf-name-table.h
if not exist source/pdf/pdf-name-table.h namedump.exe resources/pdf/names.txt include/mupdf/pdf/name-table.h source/pdf/pdf-name-table.h

cl /nologo -Iinclude scripts/fontdump.c setargv.obj
cl /nologo -Iinclude scripts/cmapdump.c setargv.obj
cl /nologo -Iinclude scripts/cquote.c setargv.obj
cl /nologo -Iinclude scripts/bin2hex.c setargv.obj

if not exist fontdump.exe goto usage
if not exist cmapdump.exe goto usage
if not exist cquote.exe goto usage
if not exist bin2hex.exe goto usage

if not exist generated/gen_cmap_cns.h cmapdump.exe generated/gen_cmap_cns.h resources\cmaps\cns\*
if not exist generated/gen_cmap_gb.h cmapdump.exe generated/gen_cmap_gb.h resources\cmaps\gb\*
if not exist generated/gen_cmap_japan.h cmapdump.exe generated/gen_cmap_japan.h resources\cmaps\japan\*
if not exist generated/gen_cmap_korea.h cmapdump.exe generated/gen_cmap_korea.h resources\cmaps\korea\*

if not exist generated/gen_adobe_ca.h bin2hex.exe generated/gen_adobe_ca.h resources/certs/AdobeCA.p7c
if not exist generated/gen_js_util.h cquote.exe generated/gen_js_util.h source/pdf/pdf-js-util.js

if not exist generated/DroidSansFallback.c fontdump.exe generated/DroidSansFallback.c resources/fonts/droid/DroidSansFallback.ttf
if not exist generated/DroidSansFallbackFull.c fontdump.exe generated/DroidSansFallbackFull.c resources/fonts/droid/DroidSansFallbackFull.ttf

if not exist generated/Dingbats.c fontdump.exe generated/Dingbats.c resources/fonts/urw/Dingbats.cff
if not exist generated/NimbusMonoPS-Bold.c fontdump.exe generated/NimbusMonoPS-Bold.c resources/fonts/urw/NimbusMonoPS-Bold.cff
if not exist generated/NimbusMonoPS-BoldItalic.c fontdump.exe generated/NimbusMonoPS-BoldItalic.c resources/fonts/urw/NimbusMonoPS-BoldItalic.cff
if not exist generated/NimbusMonoPS-Italic.c fontdump.exe generated/NimbusMonoPS-Italic.c resources/fonts/urw/NimbusMonoPS-Italic.cff
if not exist generated/NimbusMonoPS-Regular.c fontdump.exe generated/NimbusMonoPS-Regular.c resources/fonts/urw/NimbusMonoPS-Regular.cff
if not exist generated/NimbusRoman-Bold.c fontdump.exe generated/NimbusRoman-Bold.c resources/fonts/urw/NimbusRoman-Bold.cff
if not exist generated/NimbusRoman-BoldItalic.c fontdump.exe generated/NimbusRoman-BoldItalic.c resources/fonts/urw/NimbusRoman-BoldItalic.cff
if not exist generated/NimbusRoman-Regular.c fontdump.exe generated/NimbusRoman-Regular.c resources/fonts/urw/NimbusRoman-Regular.cff
if not exist generated/NimbusRoman-Italic.c fontdump.exe generated/NimbusRoman-Italic.c resources/fonts/urw/NimbusRoman-Italic.cff
if not exist generated/NimbusSans-Bold.c fontdump.exe generated/NimbusSans-Bold.c resources/fonts/urw/NimbusSans-Bold.cff
if not exist generated/NimbusSans-BoldOblique.c fontdump.exe generated/NimbusSans-BoldOblique.c resources/fonts/urw/NimbusSans-BoldOblique.cff
if not exist generated/NimbusSans-Regular.c fontdump.exe generated/NimbusSans-Regular.c resources/fonts/urw/NimbusSans-Regular.cff
if not exist generated/NimbusSans-Oblique.c fontdump.exe generated/NimbusSans-Oblique.c resources/fonts/urw/NimbusSans-Oblique.cff
if not exist generated/StandardSymbolsPS.c fontdump.exe generated/StandardSymbolsPS.c resources/fonts/urw/StandardSymbolsPS.cff

if not exist generated/CharisSIL-R.c fontdump.exe generated/CharisSIL-R.c resources/fonts/sil/CharisSIL-R.cff
if not exist generated/CharisSIL-I.c fontdump.exe generated/CharisSIL-I.c resources/fonts/sil/CharisSIL-I.cff
if not exist generated/CharisSIL-B.c fontdump.exe generated/CharisSIL-B.c resources/fonts/sil/CharisSIL-B.cff
if not exist generated/CharisSIL-BI.c fontdump.exe generated/CharisSIL-BI.c resources/fonts/sil/CharisSIL-BI.cff

if not exist generated/SourceHanSansCN-Regular.c fontdump.exe generated/SourceHanSansCN-Regular.c resources/fonts/han/SourceHanSansCN-Regular.otf
if not exist generated/SourceHanSansJP-Regular.c fontdump.exe generated/SourceHanSansJP-Regular.c resources/fonts/han/SourceHanSansJP-Regular.otf
if not exist generated/SourceHanSansKR-Regular.c fontdump.exe generated/SourceHanSansKR-Regular.c resources/fonts/han/SourceHanSansKR-Regular.otf
if not exist generated/SourceHanSansTW-Regular.c fontdump.exe generated/SourceHanSansTW-Regular.c resources/fonts/han/SourceHanSansTW-Regular.otf

if not exist generated/NotoEmoji-Regular.c fontdump.exe generated/NotoEmoji-Regular.c resources/fonts/noto/NotoEmoji-Regular.ttf
if not exist generated/NotoKufiArabic-Regular.c fontdump.exe generated/NotoKufiArabic-Regular.c resources/fonts/noto/NotoKufiArabic-Regular.ttf
if not exist generated/NotoNaskhArabic-Regular.c fontdump.exe generated/NotoNaskhArabic-Regular.c resources/fonts/noto/NotoNaskhArabic-Regular.ttf
if not exist generated/NotoNastaliqUrdu-Regular.c fontdump.exe generated/NotoNastaliqUrdu-Regular.c resources/fonts/noto/NotoNastaliqUrdu-Regular.ttf
if not exist generated/NotoSans-Regular.c fontdump.exe generated/NotoSans-Regular.c resources/fonts/noto/NotoSans-Regular.ttf
if not exist generated/NotoSansArmenian-Regular.c fontdump.exe generated/NotoSansArmenian-Regular.c resources/fonts/noto/NotoSansArmenian-Regular.ttf
if not exist generated/NotoSansAvestan-Regular.c fontdump.exe generated/NotoSansAvestan-Regular.c resources/fonts/noto/NotoSansAvestan-Regular.ttf
if not exist generated/NotoSansBalinese-Regular.c fontdump.exe generated/NotoSansBalinese-Regular.c resources/fonts/noto/NotoSansBalinese-Regular.ttf
if not exist generated/NotoSansBamum-Regular.c fontdump.exe generated/NotoSansBamum-Regular.c resources/fonts/noto/NotoSansBamum-Regular.ttf
if not exist generated/NotoSansBatak-Regular.c fontdump.exe generated/NotoSansBatak-Regular.c resources/fonts/noto/NotoSansBatak-Regular.ttf
if not exist generated/NotoSansBengali-Regular.c fontdump.exe generated/NotoSansBengali-Regular.c resources/fonts/noto/NotoSansBengali-Regular.ttf
if not exist generated/NotoSansBrahmi-Regular.c fontdump.exe generated/NotoSansBrahmi-Regular.c resources/fonts/noto/NotoSansBrahmi-Regular.ttf
if not exist generated/NotoSansBuginese-Regular.c fontdump.exe generated/NotoSansBuginese-Regular.c resources/fonts/noto/NotoSansBuginese-Regular.ttf
if not exist generated/NotoSansBuhid-Regular.c fontdump.exe generated/NotoSansBuhid-Regular.c resources/fonts/noto/NotoSansBuhid-Regular.ttf
if not exist generated/NotoSansCanadianAboriginal-Regular.c fontdump.exe generated/NotoSansCanadianAboriginal-Regular.c resources/fonts/noto/NotoSansCanadianAboriginal-Regular.ttf
if not exist generated/NotoSansCarian-Regular.c fontdump.exe generated/NotoSansCarian-Regular.c resources/fonts/noto/NotoSansCarian-Regular.ttf
if not exist generated/NotoSansCham-Regular.c fontdump.exe generated/NotoSansCham-Regular.c resources/fonts/noto/NotoSansCham-Regular.ttf
if not exist generated/NotoSansCherokee-Regular.c fontdump.exe generated/NotoSansCherokee-Regular.c resources/fonts/noto/NotoSansCherokee-Regular.ttf
if not exist generated/NotoSansCoptic-Regular.c fontdump.exe generated/NotoSansCoptic-Regular.c resources/fonts/noto/NotoSansCoptic-Regular.ttf
if not exist generated/NotoSansCuneiform-Regular.c fontdump.exe generated/NotoSansCuneiform-Regular.c resources/fonts/noto/NotoSansCuneiform-Regular.ttf
if not exist generated/NotoSansCypriot-Regular.c fontdump.exe generated/NotoSansCypriot-Regular.c resources/fonts/noto/NotoSansCypriot-Regular.ttf
if not exist generated/NotoSansDeseret-Regular.c fontdump.exe generated/NotoSansDeseret-Regular.c resources/fonts/noto/NotoSansDeseret-Regular.ttf
if not exist generated/NotoSansDevanagari-Regular.c fontdump.exe generated/NotoSansDevanagari-Regular.c resources/fonts/noto/NotoSansDevanagari-Regular.ttf
if not exist generated/NotoSansEgyptianHieroglyphs-Regular.c fontdump.exe generated/NotoSansEgyptianHieroglyphs-Regular.c resources/fonts/noto/NotoSansEgyptianHieroglyphs-Regular.ttf
if not exist generated/NotoSansEthiopic-Regular.c fontdump.exe generated/NotoSansEthiopic-Regular.c resources/fonts/noto/NotoSansEthiopic-Regular.ttf
if not exist generated/NotoSansGeorgian-Regular.c fontdump.exe generated/NotoSansGeorgian-Regular.c resources/fonts/noto/NotoSansGeorgian-Regular.ttf
if not exist generated/NotoSansGlagolitic-Regular.c fontdump.exe generated/NotoSansGlagolitic-Regular.c resources/fonts/noto/NotoSansGlagolitic-Regular.ttf
if not exist generated/NotoSansGothic-Regular.c fontdump.exe generated/NotoSansGothic-Regular.c resources/fonts/noto/NotoSansGothic-Regular.ttf
if not exist generated/NotoSansGujarati-Regular.c fontdump.exe generated/NotoSansGujarati-Regular.c resources/fonts/noto/NotoSansGujarati-Regular.ttf
if not exist generated/NotoSansGurmukhi-Regular.c fontdump.exe generated/NotoSansGurmukhi-Regular.c resources/fonts/noto/NotoSansGurmukhi-Regular.ttf
if not exist generated/NotoSansHanunoo-Regular.c fontdump.exe generated/NotoSansHanunoo-Regular.c resources/fonts/noto/NotoSansHanunoo-Regular.ttf
if not exist generated/NotoSansHebrew-Regular.c fontdump.exe generated/NotoSansHebrew-Regular.c resources/fonts/noto/NotoSansHebrew-Regular.ttf
if not exist generated/NotoSansImperialAramaic-Regular.c fontdump.exe generated/NotoSansImperialAramaic-Regular.c resources/fonts/noto/NotoSansImperialAramaic-Regular.ttf
if not exist generated/NotoSansInscriptionalPahlavi-Regular.c fontdump.exe generated/NotoSansInscriptionalPahlavi-Regular.c resources/fonts/noto/NotoSansInscriptionalPahlavi-Regular.ttf
if not exist generated/NotoSansInscriptionalParthian-Regular.c fontdump.exe generated/NotoSansInscriptionalParthian-Regular.c resources/fonts/noto/NotoSansInscriptionalParthian-Regular.ttf
if not exist generated/NotoSansJavanese-Regular.c fontdump.exe generated/NotoSansJavanese-Regular.c resources/fonts/noto/NotoSansJavanese-Regular.ttf
if not exist generated/NotoSansKaithi-Regular.c fontdump.exe generated/NotoSansKaithi-Regular.c resources/fonts/noto/NotoSansKaithi-Regular.ttf
if not exist generated/NotoSansKannada-Regular.c fontdump.exe generated/NotoSansKannada-Regular.c resources/fonts/noto/NotoSansKannada-Regular.ttf
if not exist generated/NotoSansKayahLi-Regular.c fontdump.exe generated/NotoSansKayahLi-Regular.c resources/fonts/noto/NotoSansKayahLi-Regular.ttf
if not exist generated/NotoSansKharoshthi-Regular.c fontdump.exe generated/NotoSansKharoshthi-Regular.c resources/fonts/noto/NotoSansKharoshthi-Regular.ttf
if not exist generated/NotoSansKhmer-Regular.c fontdump.exe generated/NotoSansKhmer-Regular.c resources/fonts/noto/NotoSansKhmer-Regular.ttf
if not exist generated/NotoSansLao-Regular.c fontdump.exe generated/NotoSansLao-Regular.c resources/fonts/noto/NotoSansLao-Regular.ttf
if not exist generated/NotoSansLepcha-Regular.c fontdump.exe generated/NotoSansLepcha-Regular.c resources/fonts/noto/NotoSansLepcha-Regular.ttf
if not exist generated/NotoSansLimbu-Regular.c fontdump.exe generated/NotoSansLimbu-Regular.c resources/fonts/noto/NotoSansLimbu-Regular.ttf
if not exist generated/NotoSansLinearB-Regular.c fontdump.exe generated/NotoSansLinearB-Regular.c resources/fonts/noto/NotoSansLinearB-Regular.ttf
if not exist generated/NotoSansLisu-Regular.c fontdump.exe generated/NotoSansLisu-Regular.c resources/fonts/noto/NotoSansLisu-Regular.ttf
if not exist generated/NotoSansLycian-Regular.c fontdump.exe generated/NotoSansLycian-Regular.c resources/fonts/noto/NotoSansLycian-Regular.ttf
if not exist generated/NotoSansLydian-Regular.c fontdump.exe generated/NotoSansLydian-Regular.c resources/fonts/noto/NotoSansLydian-Regular.ttf
if not exist generated/NotoSansMalayalam-Regular.c fontdump.exe generated/NotoSansMalayalam-Regular.c resources/fonts/noto/NotoSansMalayalam-Regular.ttf
if not exist generated/NotoSansMandaic-Regular.c fontdump.exe generated/NotoSansMandaic-Regular.c resources/fonts/noto/NotoSansMandaic-Regular.ttf
if not exist generated/NotoSansMeeteiMayek-Regular.c fontdump.exe generated/NotoSansMeeteiMayek-Regular.c resources/fonts/noto/NotoSansMeeteiMayek-Regular.ttf
if not exist generated/NotoSansMongolian-Regular.c fontdump.exe generated/NotoSansMongolian-Regular.c resources/fonts/noto/NotoSansMongolian-Regular.ttf
if not exist generated/NotoSansMyanmar-Regular.c fontdump.exe generated/NotoSansMyanmar-Regular.c resources/fonts/noto/NotoSansMyanmar-Regular.ttf
if not exist generated/NotoSansNKo-Regular.c fontdump.exe generated/NotoSansNKo-Regular.c resources/fonts/noto/NotoSansNKo-Regular.ttf
if not exist generated/NotoSansNewTaiLue-Regular.c fontdump.exe generated/NotoSansNewTaiLue-Regular.c resources/fonts/noto/NotoSansNewTaiLue-Regular.ttf
if not exist generated/NotoSansOgham-Regular.c fontdump.exe generated/NotoSansOgham-Regular.c resources/fonts/noto/NotoSansOgham-Regular.ttf
if not exist generated/NotoSansOlChiki-Regular.c fontdump.exe generated/NotoSansOlChiki-Regular.c resources/fonts/noto/NotoSansOlChiki-Regular.ttf
if not exist generated/NotoSansOldItalic-Regular.c fontdump.exe generated/NotoSansOldItalic-Regular.c resources/fonts/noto/NotoSansOldItalic-Regular.ttf
if not exist generated/NotoSansOldPersian-Regular.c fontdump.exe generated/NotoSansOldPersian-Regular.c resources/fonts/noto/NotoSansOldPersian-Regular.ttf
if not exist generated/NotoSansOldSouthArabian-Regular.c fontdump.exe generated/NotoSansOldSouthArabian-Regular.c resources/fonts/noto/NotoSansOldSouthArabian-Regular.ttf
if not exist generated/NotoSansOldTurkic-Regular.c fontdump.exe generated/NotoSansOldTurkic-Regular.c resources/fonts/noto/NotoSansOldTurkic-Regular.ttf
if not exist generated/NotoSansOriya-Regular.c fontdump.exe generated/NotoSansOriya-Regular.c resources/fonts/noto/NotoSansOriya-Regular.ttf
if not exist generated/NotoSansOsmanya-Regular.c fontdump.exe generated/NotoSansOsmanya-Regular.c resources/fonts/noto/NotoSansOsmanya-Regular.ttf
if not exist generated/NotoSansPhagsPa-Regular.c fontdump.exe generated/NotoSansPhagsPa-Regular.c resources/fonts/noto/NotoSansPhagsPa-Regular.ttf
if not exist generated/NotoSansPhoenician-Regular.c fontdump.exe generated/NotoSansPhoenician-Regular.c resources/fonts/noto/NotoSansPhoenician-Regular.ttf
if not exist generated/NotoSansRejang-Regular.c fontdump.exe generated/NotoSansRejang-Regular.c resources/fonts/noto/NotoSansRejang-Regular.ttf
if not exist generated/NotoSansRunic-Regular.c fontdump.exe generated/NotoSansRunic-Regular.c resources/fonts/noto/NotoSansRunic-Regular.ttf
if not exist generated/NotoSansSamaritan-Regular.c fontdump.exe generated/NotoSansSamaritan-Regular.c resources/fonts/noto/NotoSansSamaritan-Regular.ttf
if not exist generated/NotoSansSaurashtra-Regular.c fontdump.exe generated/NotoSansSaurashtra-Regular.c resources/fonts/noto/NotoSansSaurashtra-Regular.ttf
if not exist generated/NotoSansShavian-Regular.c fontdump.exe generated/NotoSansShavian-Regular.c resources/fonts/noto/NotoSansShavian-Regular.ttf
if not exist generated/NotoSansSinhala-Regular.c fontdump.exe generated/NotoSansSinhala-Regular.c resources/fonts/noto/NotoSansSinhala-Regular.ttf
if not exist generated/NotoSansSundanese-Regular.c fontdump.exe generated/NotoSansSundanese-Regular.c resources/fonts/noto/NotoSansSundanese-Regular.ttf
if not exist generated/NotoSansSylotiNagri-Regular.c fontdump.exe generated/NotoSansSylotiNagri-Regular.c resources/fonts/noto/NotoSansSylotiNagri-Regular.ttf
if not exist generated/NotoSansSymbols-Regular.c fontdump.exe generated/NotoSansSymbols-Regular.c resources/fonts/noto/NotoSansSymbols-Regular.ttf
if not exist generated/NotoSansSyriacEastern-Regular.c fontdump.exe generated/NotoSansSyriacEastern-Regular.c resources/fonts/noto/NotoSansSyriacEastern-Regular.ttf
if not exist generated/NotoSansSyriacEstrangela-Regular.c fontdump.exe generated/NotoSansSyriacEstrangela-Regular.c resources/fonts/noto/NotoSansSyriacEstrangela-Regular.ttf
if not exist generated/NotoSansSyriacWestern-Regular.c fontdump.exe generated/NotoSansSyriacWestern-Regular.c resources/fonts/noto/NotoSansSyriacWestern-Regular.ttf
if not exist generated/NotoSansTagalog-Regular.c fontdump.exe generated/NotoSansTagalog-Regular.c resources/fonts/noto/NotoSansTagalog-Regular.ttf
if not exist generated/NotoSansTagbanwa-Regular.c fontdump.exe generated/NotoSansTagbanwa-Regular.c resources/fonts/noto/NotoSansTagbanwa-Regular.ttf
if not exist generated/NotoSansTaiLe-Regular.c fontdump.exe generated/NotoSansTaiLe-Regular.c resources/fonts/noto/NotoSansTaiLe-Regular.ttf
if not exist generated/NotoSansTaiTham-Regular.c fontdump.exe generated/NotoSansTaiTham-Regular.c resources/fonts/noto/NotoSansTaiTham-Regular.ttf
if not exist generated/NotoSansTaiViet-Regular.c fontdump.exe generated/NotoSansTaiViet-Regular.c resources/fonts/noto/NotoSansTaiViet-Regular.ttf
if not exist generated/NotoSansTamil-Regular.c fontdump.exe generated/NotoSansTamil-Regular.c resources/fonts/noto/NotoSansTamil-Regular.ttf
if not exist generated/NotoSansTelugu-Regular.c fontdump.exe generated/NotoSansTelugu-Regular.c resources/fonts/noto/NotoSansTelugu-Regular.ttf
if not exist generated/NotoSansThaana-Regular.c fontdump.exe generated/NotoSansThaana-Regular.c resources/fonts/noto/NotoSansThaana-Regular.ttf
if not exist generated/NotoSansThai-Regular.c fontdump.exe generated/NotoSansThai-Regular.c resources/fonts/noto/NotoSansThai-Regular.ttf
if not exist generated/NotoSansTibetan-Regular.c fontdump.exe generated/NotoSansTibetan-Regular.c resources/fonts/noto/NotoSansTibetan-Regular.ttf
if not exist generated/NotoSansTifinagh-Regular.c fontdump.exe generated/NotoSansTifinagh-Regular.c resources/fonts/noto/NotoSansTifinagh-Regular.ttf
if not exist generated/NotoSansUgaritic-Regular.c fontdump.exe generated/NotoSansUgaritic-Regular.c resources/fonts/noto/NotoSansUgaritic-Regular.ttf
if not exist generated/NotoSansVai-Regular.c fontdump.exe generated/NotoSansVai-Regular.c resources/fonts/noto/NotoSansVai-Regular.ttf
if not exist generated/NotoSansYi-Regular.c fontdump.exe generated/NotoSansYi-Regular.c resources/fonts/noto/NotoSansYi-Regular.ttf
if not exist generated/NotoSerif-Regular.c fontdump.exe generated/NotoSerif-Regular.c resources/fonts/noto/NotoSerif-Regular.ttf
if not exist generated/NotoSerifArmenian-Regular.c fontdump.exe generated/NotoSerifArmenian-Regular.c resources/fonts/noto/NotoSerifArmenian-Regular.ttf
if not exist generated/NotoSerifBengali-Regular.c fontdump.exe generated/NotoSerifBengali-Regular.c resources/fonts/noto/NotoSerifBengali-Regular.ttf
if not exist generated/NotoSerifGeorgian-Regular.c fontdump.exe generated/NotoSerifGeorgian-Regular.c resources/fonts/noto/NotoSerifGeorgian-Regular.ttf
if not exist generated/NotoSerifGujarati-Regular.c fontdump.exe generated/NotoSerifGujarati-Regular.c resources/fonts/noto/NotoSerifGujarati-Regular.ttf
if not exist generated/NotoSerifKannada-Regular.c fontdump.exe generated/NotoSerifKannada-Regular.c resources/fonts/noto/NotoSerifKannada-Regular.ttf
if not exist generated/NotoSerifKhmer-Regular.c fontdump.exe generated/NotoSerifKhmer-Regular.c resources/fonts/noto/NotoSerifKhmer-Regular.ttf
if not exist generated/NotoSerifLao-Regular.c fontdump.exe generated/NotoSerifLao-Regular.c resources/fonts/noto/NotoSerifLao-Regular.ttf
if not exist generated/NotoSerifMalayalam-Regular.c fontdump.exe generated/NotoSerifMalayalam-Regular.c resources/fonts/noto/NotoSerifMalayalam-Regular.ttf
if not exist generated/NotoSerifTamil-Regular.c fontdump.exe generated/NotoSerifTamil-Regular.c resources/fonts/noto/NotoSerifTamil-Regular.ttf
if not exist generated/NotoSerifTelugu-Regular.c fontdump.exe generated/NotoSerifTelugu-Regular.c resources/fonts/noto/NotoSerifTelugu-Regular.ttf
if not exist generated/NotoSerifThai-Regular.c fontdump.exe generated/NotoSerifThai-Regular.c resources/fonts/noto/NotoSerifThai-Regular.ttf

del cmapdump.obj fontdump.obj cquote.obj bin2hex.obj cmapdump.exe fontdump.exe cquote.exe bin2hex.exe

goto fin

:usage
echo ERROR: Run this script in the mupdf directory.
echo ERROR: Run this script in a Visual Studio command prompt.
pause

:fin
