# excl.dat contains all glyphs which do not have a unicode encoding in the original otf,
# and all glyphs in the PUA.

tx -cff +S -n -gx $(cat excl.dat) CharisSIL-5.000-developer/sources/CharisSIL-R-designsource.otf > CharisSIL-R.cff
tx -cff +S -n -gx $(cat excl.dat) CharisSIL-5.000-developer/sources/CharisSIL-I-designsource.otf > CharisSIL-I.cff
tx -cff +S -n -gx $(cat excl.dat) CharisSIL-5.000-developer/sources/CharisSIL-B-designsource.otf > CharisSIL-B.cff
tx -cff +S -n -gx $(cat excl.dat) CharisSIL-5.000-developer/sources/CharisSIL-BI-designsource.otf > CharisSIL-BI.cff
