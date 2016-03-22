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
if not exist generated/gen_js_util.h cquote.exe generated/gen_js_util.h source/pdf/js/pdf-util.js

if not exist generated/DroidSansFallback.ttc fontdump.exe generated/DroidSansFallback.ttc resources/fonts/droid/DroidSansFallback.ttc
if not exist generated/DroidSansFallbackFull.ttc fontdump.exe generated/DroidSansFallbackFull.ttc resources/fonts/droid/DroidSansFallbackFull.ttc

if not exist generated/Dingbats.cff fontdump.exe generated/Dingbats.cff resources/fonts/urw/Dingbats.cff
if not exist generated/NimbusMono-Bold.cff fontdump.exe generated/NimbusMono-Bold.cff resources/fonts/urw/NimbusMono-Bold.cff
if not exist generated/NimbusMono-BoldOblique.cff fontdump.exe generated/NimbusMono-BoldOblique.cff resources/fonts/urw/NimbusMono-BoldOblique.cff
if not exist generated/NimbusMono-Oblique.cff fontdump.exe generated/NimbusMono-Oblique.cff resources/fonts/urw/NimbusMono-Oblique.cff
if not exist generated/NimbusMono-Regular.cff fontdump.exe generated/NimbusMono-Regular.cff resources/fonts/urw/NimbusMono-Regular.cff
if not exist generated/NimbusRomNo9L-Med.cff fontdump.exe generated/NimbusRomNo9L-Med.cff resources/fonts/urw/NimbusRomNo9L-Med.cff
if not exist generated/NimbusRomNo9L-MedIta.cff fontdump.exe generated/NimbusRomNo9L-MedIta.cff resources/fonts/urw/NimbusRomNo9L-MedIta.cff
if not exist generated/NimbusRomNo9L-Reg.cff fontdump.exe generated/NimbusRomNo9L-Reg.cff resources/fonts/urw/NimbusRomNo9L-Reg.cff
if not exist generated/NimbusRomNo9L-RegIta.cff fontdump.exe generated/NimbusRomNo9L-RegIta.cff resources/fonts/urw/NimbusRomNo9L-RegIta.cff
if not exist generated/NimbusSanL-Bol.cff fontdump.exe generated/NimbusSanL-Bol.cff resources/fonts/urw/NimbusSanL-Bol.cff
if not exist generated/NimbusSanL-BolIta.cff fontdump.exe generated/NimbusSanL-BolIta.cff resources/fonts/urw/NimbusSanL-BolIta.cff
if not exist generated/NimbusSanL-Reg.cff fontdump.exe generated/NimbusSanL-Reg.cff resources/fonts/urw/NimbusSanL-Reg.cff
if not exist generated/NimbusSanL-RegIta.cff fontdump.exe generated/NimbusSanL-RegIta.cff resources/fonts/urw/NimbusSanL-RegIta.cff
if not exist generated/StandardSymL.cff fontdump.exe resources/fonts/urw/StandardSymL.cff resources/fonts/urw/StandardSymL.cff

if not exist generated/NotoEmoji-Regular.ttf fontdump.exe generated/NotoEmoji-Regular.ttf resources/fonts/noto/NotoEmoji-Regular.ttf
if not exist generated/NotoKufiArabic-Regular.ttf fontdump.exe generated/NotoKufiArabic-Regular.ttf resources/fonts/noto/NotoKufiArabic-Regular.ttf
if not exist generated/NotoNaskhArabic-Regular.ttf fontdump.exe generated/NotoNaskhArabic-Regular.ttf resources/fonts/noto/NotoNaskhArabic-Regular.ttf
if not exist generated/NotoNastaliqUrdu-Regular.ttf fontdump.exe generated/NotoNastaliqUrdu-Regular.ttf resources/fonts/noto/NotoNastaliqUrdu-Regular.ttf
if not exist generated/NotoSans-Regular.ttf fontdump.exe generated/NotoSans-Regular.ttf resources/fonts/noto/NotoSans-Regular.ttf
if not exist generated/NotoSansArmenian-Regular.ttf fontdump.exe generated/NotoSansArmenian-Regular.ttf resources/fonts/noto/NotoSansArmenian-Regular.ttf
if not exist generated/NotoSansAvestan-Regular.ttf fontdump.exe generated/NotoSansAvestan-Regular.ttf resources/fonts/noto/NotoSansAvestan-Regular.ttf
if not exist generated/NotoSansBalinese-Regular.ttf fontdump.exe generated/NotoSansBalinese-Regular.ttf resources/fonts/noto/NotoSansBalinese-Regular.ttf
if not exist generated/NotoSansBamum-Regular.ttf fontdump.exe generated/NotoSansBamum-Regular.ttf resources/fonts/noto/NotoSansBamum-Regular.ttf
if not exist generated/NotoSansBatak-Regular.ttf fontdump.exe generated/NotoSansBatak-Regular.ttf resources/fonts/noto/NotoSansBatak-Regular.ttf
if not exist generated/NotoSansBengali-Regular.ttf fontdump.exe generated/NotoSansBengali-Regular.ttf resources/fonts/noto/NotoSansBengali-Regular.ttf
if not exist generated/NotoSansBrahmi-Regular.ttf fontdump.exe generated/NotoSansBrahmi-Regular.ttf resources/fonts/noto/NotoSansBrahmi-Regular.ttf
if not exist generated/NotoSansBuginese-Regular.ttf fontdump.exe generated/NotoSansBuginese-Regular.ttf resources/fonts/noto/NotoSansBuginese-Regular.ttf
if not exist generated/NotoSansBuhid-Regular.ttf fontdump.exe generated/NotoSansBuhid-Regular.ttf resources/fonts/noto/NotoSansBuhid-Regular.ttf
if not exist generated/NotoSansCanadianAboriginal-Regular.ttf fontdump.exe generated/NotoSansCanadianAboriginal-Regular.ttf resources/fonts/noto/NotoSansCanadianAboriginal-Regular.ttf
if not exist generated/NotoSansCarian-Regular.ttf fontdump.exe generated/NotoSansCarian-Regular.ttf resources/fonts/noto/NotoSansCarian-Regular.ttf
if not exist generated/NotoSansCham-Regular.ttf fontdump.exe generated/NotoSansCham-Regular.ttf resources/fonts/noto/NotoSansCham-Regular.ttf
if not exist generated/NotoSansCherokee-Regular.ttf fontdump.exe generated/NotoSansCherokee-Regular.ttf resources/fonts/noto/NotoSansCherokee-Regular.ttf
if not exist generated/NotoSansCoptic-Regular.ttf fontdump.exe generated/NotoSansCoptic-Regular.ttf resources/fonts/noto/NotoSansCoptic-Regular.ttf
if not exist generated/NotoSansCuneiform-Regular.ttf fontdump.exe generated/NotoSansCuneiform-Regular.ttf resources/fonts/noto/NotoSansCuneiform-Regular.ttf
if not exist generated/NotoSansCypriot-Regular.ttf fontdump.exe generated/NotoSansCypriot-Regular.ttf resources/fonts/noto/NotoSansCypriot-Regular.ttf
if not exist generated/NotoSansDeseret-Regular.ttf fontdump.exe generated/NotoSansDeseret-Regular.ttf resources/fonts/noto/NotoSansDeseret-Regular.ttf
if not exist generated/NotoSansDevanagari-Regular.ttf fontdump.exe generated/NotoSansDevanagari-Regular.ttf resources/fonts/noto/NotoSansDevanagari-Regular.ttf
if not exist generated/NotoSansEgyptianHieroglyphs-Regular.ttf fontdump.exe generated/NotoSansEgyptianHieroglyphs-Regular.ttf resources/fonts/noto/NotoSansEgyptianHieroglyphs-Regular.ttf
if not exist generated/NotoSansEthiopic-Regular.ttf fontdump.exe generated/NotoSansEthiopic-Regular.ttf resources/fonts/noto/NotoSansEthiopic-Regular.ttf
if not exist generated/NotoSansGeorgian-Regular.ttf fontdump.exe generated/NotoSansGeorgian-Regular.ttf resources/fonts/noto/NotoSansGeorgian-Regular.ttf
if not exist generated/NotoSansGlagolitic-Regular.ttf fontdump.exe generated/NotoSansGlagolitic-Regular.ttf resources/fonts/noto/NotoSansGlagolitic-Regular.ttf
if not exist generated/NotoSansGothic-Regular.ttf fontdump.exe generated/NotoSansGothic-Regular.ttf resources/fonts/noto/NotoSansGothic-Regular.ttf
if not exist generated/NotoSansGujarati-Regular.ttf fontdump.exe generated/NotoSansGujarati-Regular.ttf resources/fonts/noto/NotoSansGujarati-Regular.ttf
if not exist generated/NotoSansGurmukhi-Regular.ttf fontdump.exe generated/NotoSansGurmukhi-Regular.ttf resources/fonts/noto/NotoSansGurmukhi-Regular.ttf
if not exist generated/NotoSansHanunoo-Regular.ttf fontdump.exe generated/NotoSansHanunoo-Regular.ttf resources/fonts/noto/NotoSansHanunoo-Regular.ttf
if not exist generated/NotoSansHebrew-Regular.ttf fontdump.exe generated/NotoSansHebrew-Regular.ttf resources/fonts/noto/NotoSansHebrew-Regular.ttf
if not exist generated/NotoSansImperialAramaic-Regular.ttf fontdump.exe generated/NotoSansImperialAramaic-Regular.ttf resources/fonts/noto/NotoSansImperialAramaic-Regular.ttf
if not exist generated/NotoSansInscriptionalPahlavi-Regular.ttf fontdump.exe generated/NotoSansInscriptionalPahlavi-Regular.ttf resources/fonts/noto/NotoSansInscriptionalPahlavi-Regular.ttf
if not exist generated/NotoSansInscriptionalParthian-Regular.ttf fontdump.exe generated/NotoSansInscriptionalParthian-Regular.ttf resources/fonts/noto/NotoSansInscriptionalParthian-Regular.ttf
if not exist generated/NotoSansJavanese-Regular.ttf fontdump.exe generated/NotoSansJavanese-Regular.ttf resources/fonts/noto/NotoSansJavanese-Regular.ttf
if not exist generated/NotoSansKaithi-Regular.ttf fontdump.exe generated/NotoSansKaithi-Regular.ttf resources/fonts/noto/NotoSansKaithi-Regular.ttf
if not exist generated/NotoSansKannada-Regular.ttf fontdump.exe generated/NotoSansKannada-Regular.ttf resources/fonts/noto/NotoSansKannada-Regular.ttf
if not exist generated/NotoSansKayahLi-Regular.ttf fontdump.exe generated/NotoSansKayahLi-Regular.ttf resources/fonts/noto/NotoSansKayahLi-Regular.ttf
if not exist generated/NotoSansKharoshthi-Regular.ttf fontdump.exe generated/NotoSansKharoshthi-Regular.ttf resources/fonts/noto/NotoSansKharoshthi-Regular.ttf
if not exist generated/NotoSansKhmer-Regular.ttf fontdump.exe generated/NotoSansKhmer-Regular.ttf resources/fonts/noto/NotoSansKhmer-Regular.ttf
if not exist generated/NotoSansLao-Regular.ttf fontdump.exe generated/NotoSansLao-Regular.ttf resources/fonts/noto/NotoSansLao-Regular.ttf
if not exist generated/NotoSansLepcha-Regular.ttf fontdump.exe generated/NotoSansLepcha-Regular.ttf resources/fonts/noto/NotoSansLepcha-Regular.ttf
if not exist generated/NotoSansLimbu-Regular.ttf fontdump.exe generated/NotoSansLimbu-Regular.ttf resources/fonts/noto/NotoSansLimbu-Regular.ttf
if not exist generated/NotoSansLinearB-Regular.ttf fontdump.exe generated/NotoSansLinearB-Regular.ttf resources/fonts/noto/NotoSansLinearB-Regular.ttf
if not exist generated/NotoSansLisu-Regular.ttf fontdump.exe generated/NotoSansLisu-Regular.ttf resources/fonts/noto/NotoSansLisu-Regular.ttf
if not exist generated/NotoSansLycian-Regular.ttf fontdump.exe generated/NotoSansLycian-Regular.ttf resources/fonts/noto/NotoSansLycian-Regular.ttf
if not exist generated/NotoSansLydian-Regular.ttf fontdump.exe generated/NotoSansLydian-Regular.ttf resources/fonts/noto/NotoSansLydian-Regular.ttf
if not exist generated/NotoSansMalayalam-Regular.ttf fontdump.exe generated/NotoSansMalayalam-Regular.ttf resources/fonts/noto/NotoSansMalayalam-Regular.ttf
if not exist generated/NotoSansMandaic-Regular.ttf fontdump.exe generated/NotoSansMandaic-Regular.ttf resources/fonts/noto/NotoSansMandaic-Regular.ttf
if not exist generated/NotoSansMeeteiMayek-Regular.ttf fontdump.exe generated/NotoSansMeeteiMayek-Regular.ttf resources/fonts/noto/NotoSansMeeteiMayek-Regular.ttf
if not exist generated/NotoSansMongolian-Regular.ttf fontdump.exe generated/NotoSansMongolian-Regular.ttf resources/fonts/noto/NotoSansMongolian-Regular.ttf
if not exist generated/NotoSansMyanmar-Regular.ttf fontdump.exe generated/NotoSansMyanmar-Regular.ttf resources/fonts/noto/NotoSansMyanmar-Regular.ttf
if not exist generated/NotoSansNKo-Regular.ttf fontdump.exe generated/NotoSansNKo-Regular.ttf resources/fonts/noto/NotoSansNKo-Regular.ttf
if not exist generated/NotoSansNewTaiLue-Regular.ttf fontdump.exe generated/NotoSansNewTaiLue-Regular.ttf resources/fonts/noto/NotoSansNewTaiLue-Regular.ttf
if not exist generated/NotoSansOgham-Regular.ttf fontdump.exe generated/NotoSansOgham-Regular.ttf resources/fonts/noto/NotoSansOgham-Regular.ttf
if not exist generated/NotoSansOlChiki-Regular.ttf fontdump.exe generated/NotoSansOlChiki-Regular.ttf resources/fonts/noto/NotoSansOlChiki-Regular.ttf
if not exist generated/NotoSansOldItalic-Regular.ttf fontdump.exe generated/NotoSansOldItalic-Regular.ttf resources/fonts/noto/NotoSansOldItalic-Regular.ttf
if not exist generated/NotoSansOldPersian-Regular.ttf fontdump.exe generated/NotoSansOldPersian-Regular.ttf resources/fonts/noto/NotoSansOldPersian-Regular.ttf
if not exist generated/NotoSansOldSouthArabian-Regular.ttf fontdump.exe generated/NotoSansOldSouthArabian-Regular.ttf resources/fonts/noto/NotoSansOldSouthArabian-Regular.ttf
if not exist generated/NotoSansOldTurkic-Regular.ttf fontdump.exe generated/NotoSansOldTurkic-Regular.ttf resources/fonts/noto/NotoSansOldTurkic-Regular.ttf
if not exist generated/NotoSansOriya-Regular.ttf fontdump.exe generated/NotoSansOriya-Regular.ttf resources/fonts/noto/NotoSansOriya-Regular.ttf
if not exist generated/NotoSansOsmanya-Regular.ttf fontdump.exe generated/NotoSansOsmanya-Regular.ttf resources/fonts/noto/NotoSansOsmanya-Regular.ttf
if not exist generated/NotoSansPhagsPa-Regular.ttf fontdump.exe generated/NotoSansPhagsPa-Regular.ttf resources/fonts/noto/NotoSansPhagsPa-Regular.ttf
if not exist generated/NotoSansPhoenician-Regular.ttf fontdump.exe generated/NotoSansPhoenician-Regular.ttf resources/fonts/noto/NotoSansPhoenician-Regular.ttf
if not exist generated/NotoSansRejang-Regular.ttf fontdump.exe generated/NotoSansRejang-Regular.ttf resources/fonts/noto/NotoSansRejang-Regular.ttf
if not exist generated/NotoSansRunic-Regular.ttf fontdump.exe generated/NotoSansRunic-Regular.ttf resources/fonts/noto/NotoSansRunic-Regular.ttf
if not exist generated/NotoSansSamaritan-Regular.ttf fontdump.exe generated/NotoSansSamaritan-Regular.ttf resources/fonts/noto/NotoSansSamaritan-Regular.ttf
if not exist generated/NotoSansSaurashtra-Regular.ttf fontdump.exe generated/NotoSansSaurashtra-Regular.ttf resources/fonts/noto/NotoSansSaurashtra-Regular.ttf
if not exist generated/NotoSansShavian-Regular.ttf fontdump.exe generated/NotoSansShavian-Regular.ttf resources/fonts/noto/NotoSansShavian-Regular.ttf
if not exist generated/NotoSansSinhala-Regular.ttf fontdump.exe generated/NotoSansSinhala-Regular.ttf resources/fonts/noto/NotoSansSinhala-Regular.ttf
if not exist generated/NotoSansSundanese-Regular.ttf fontdump.exe generated/NotoSansSundanese-Regular.ttf resources/fonts/noto/NotoSansSundanese-Regular.ttf
if not exist generated/NotoSansSylotiNagri-Regular.ttf fontdump.exe generated/NotoSansSylotiNagri-Regular.ttf resources/fonts/noto/NotoSansSylotiNagri-Regular.ttf
if not exist generated/NotoSansSymbols-Regular.ttf fontdump.exe generated/NotoSansSymbols-Regular.ttf resources/fonts/noto/NotoSansSymbols-Regular.ttf
if not exist generated/NotoSansSyriacEastern-Regular.ttf fontdump.exe generated/NotoSansSyriacEastern-Regular.ttf resources/fonts/noto/NotoSansSyriacEastern-Regular.ttf
if not exist generated/NotoSansSyriacEstrangela-Regular.ttf fontdump.exe generated/NotoSansSyriacEstrangela-Regular.ttf resources/fonts/noto/NotoSansSyriacEstrangela-Regular.ttf
if not exist generated/NotoSansSyriacWestern-Regular.ttf fontdump.exe generated/NotoSansSyriacWestern-Regular.ttf resources/fonts/noto/NotoSansSyriacWestern-Regular.ttf
if not exist generated/NotoSansTagalog-Regular.ttf fontdump.exe generated/NotoSansTagalog-Regular.ttf resources/fonts/noto/NotoSansTagalog-Regular.ttf
if not exist generated/NotoSansTagbanwa-Regular.ttf fontdump.exe generated/NotoSansTagbanwa-Regular.ttf resources/fonts/noto/NotoSansTagbanwa-Regular.ttf
if not exist generated/NotoSansTaiLe-Regular.ttf fontdump.exe generated/NotoSansTaiLe-Regular.ttf resources/fonts/noto/NotoSansTaiLe-Regular.ttf
if not exist generated/NotoSansTaiTham-Regular.ttf fontdump.exe generated/NotoSansTaiTham-Regular.ttf resources/fonts/noto/NotoSansTaiTham-Regular.ttf
if not exist generated/NotoSansTaiViet-Regular.ttf fontdump.exe generated/NotoSansTaiViet-Regular.ttf resources/fonts/noto/NotoSansTaiViet-Regular.ttf
if not exist generated/NotoSansTamil-Regular.ttf fontdump.exe generated/NotoSansTamil-Regular.ttf resources/fonts/noto/NotoSansTamil-Regular.ttf
if not exist generated/NotoSansTelugu-Regular.ttf fontdump.exe generated/NotoSansTelugu-Regular.ttf resources/fonts/noto/NotoSansTelugu-Regular.ttf
if not exist generated/NotoSansThaana-Regular.ttf fontdump.exe generated/NotoSansThaana-Regular.ttf resources/fonts/noto/NotoSansThaana-Regular.ttf
if not exist generated/NotoSansThai-Regular.ttf fontdump.exe generated/NotoSansThai-Regular.ttf resources/fonts/noto/NotoSansThai-Regular.ttf
if not exist generated/NotoSansTibetan-Regular.ttf fontdump.exe generated/NotoSansTibetan-Regular.ttf resources/fonts/noto/NotoSansTibetan-Regular.ttf
if not exist generated/NotoSansTifinagh-Regular.ttf fontdump.exe generated/NotoSansTifinagh-Regular.ttf resources/fonts/noto/NotoSansTifinagh-Regular.ttf
if not exist generated/NotoSansUgaritic-Regular.ttf fontdump.exe generated/NotoSansUgaritic-Regular.ttf resources/fonts/noto/NotoSansUgaritic-Regular.ttf
if not exist generated/NotoSansVai-Regular.ttf fontdump.exe generated/NotoSansVai-Regular.ttf resources/fonts/noto/NotoSansVai-Regular.ttf
if not exist generated/NotoSansYi-Regular.ttf fontdump.exe generated/NotoSansYi-Regular.ttf resources/fonts/noto/NotoSansYi-Regular.ttf
if not exist generated/NotoSerif-Regular.ttf fontdump.exe generated/NotoSerif-Regular.ttf resources/fonts/noto/NotoSerif-Regular.ttf
if not exist generated/NotoSerifArmenian-Regular.ttf fontdump.exe generated/NotoSerifArmenian-Regular.ttf resources/fonts/noto/NotoSerifArmenian-Regular.ttf
if not exist generated/NotoSerifBengali-Regular.ttf fontdump.exe generated/NotoSerifBengali-Regular.ttf resources/fonts/noto/NotoSerifBengali-Regular.ttf
if not exist generated/NotoSerifGeorgian-Regular.ttf fontdump.exe generated/NotoSerifGeorgian-Regular.ttf resources/fonts/noto/NotoSerifGeorgian-Regular.ttf
if not exist generated/NotoSerifGujarati-Regular.ttf fontdump.exe generated/NotoSerifGujarati-Regular.ttf resources/fonts/noto/NotoSerifGujarati-Regular.ttf
if not exist generated/NotoSerifKannada-Regular.ttf fontdump.exe generated/NotoSerifKannada-Regular.ttf resources/fonts/noto/NotoSerifKannada-Regular.ttf
if not exist generated/NotoSerifKhmer-Regular.ttf fontdump.exe generated/NotoSerifKhmer-Regular.ttf resources/fonts/noto/NotoSerifKhmer-Regular.ttf
if not exist generated/NotoSerifLao-Regular.ttf fontdump.exe generated/NotoSerifLao-Regular.ttf resources/fonts/noto/NotoSerifLao-Regular.ttf
if not exist generated/NotoSerifMalayalam-Regular.ttf fontdump.exe generated/NotoSerifMalayalam-Regular.ttf resources/fonts/noto/NotoSerifMalayalam-Regular.ttf
if not exist generated/NotoSerifTamil-Regular.ttf fontdump.exe generated/NotoSerifTamil-Regular.ttf resources/fonts/noto/NotoSerifTamil-Regular.ttf
if not exist generated/NotoSerifTelugu-Regular.ttf fontdump.exe generated/NotoSerifTelugu-Regular.ttf resources/fonts/noto/NotoSerifTelugu-Regular.ttf
if not exist generated/NotoSerifThai-Regular.ttf fontdump.exe generated/NotoSerifThai-Regular.ttf resources/fonts/noto/NotoSerifThai-Regular.ttf

del cmapdump.obj fontdump.obj cquote.obj bin2hex.obj cmapdump.exe fontdump.exe cquote.exe bin2hex.exe

goto fin

:usage
echo ERROR: Run this script in the mupdf directory.
echo ERROR: Run this script in a Visual Studio command prompt.
pause

:fin
