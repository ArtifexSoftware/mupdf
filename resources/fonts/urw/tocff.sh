EXCL_PCL=\
uniEFBF,uniEFC0,uniEFC1,uniEFC2,uniEFC3,uniEFC4,uniEFC5,uniEFC6,\
uniEFC7,uniEFC8,uniEFC9,uniEFCA,uniEFCB,uniEFCC,uniEFCD,uniEFCE,\
uniEFCF,uniEFD0,uniEFD1,uniEFD2,uniEFD3,uniEFD4,uniEFD5,uniEFD6,\
uniEFD7,uniEFD8,uniEFD9,uniEFDA,uniEFDB,uniEFDC,uniEFDD,uniEFDE,\
uniEFDF,uniEFE0,uniEFE1,uniEFE2,uniEFE3,uniEFE4,uniEFE5,uniEFE6,\
uniEFE7,uniEFE8,uniEFE9,uniEFEA,uniEFEB,uniEFEC,uniEFFA,uniEFFB,\
uniEFFC,uniEFFD,uniEFFE,uniEFFF

EXCL_BOX=\
ltshade,shade,dkshade,SF110000,SF090000,SF190000,SF200000,SF210000,\
SF220000,SF230000,SF240000,SF250000,SF260000,SF270000,SF280000,SF030000,\
SF020000,SF070000,SF060000,SF080000,SF100000,SF050000,SF360000,SF370000,\
SF380000,SF390000,SF400000,SF410000,SF420000,SF430000,SF440000,SF450000,\
SF460000,SF470000,SF480000,SF490000,SF500000,SF510000,SF520000,SF530000,\
SF540000,SF040000,SF010000,block,rtblock,lfblock,dnblock,upblock

EXCL_SYM=\
smileface,invsmileface,heart,diamond,club,spade,male,female,\
musicalnote,sun,invbullet,circle,invcircle,filledrect,filledbox,uni25A1,\
triagup,arrowright,arrowleft,arrowboth,arrowup,arrowdown,arrowupdn,\
arrowupdnbse,lozenge,triagdn,H18533,carriagereturn,angleleft,angleright,\
universal,aleph,existential,Ifraktur,Rfraktur,gradient,Delta,\
arrowdbldown,arrowdblup,notequal,equivalence,radical,integral,integraltp,\
integralbt,approxequal,lessequal,greaterequal,revlogicalnot,union,\
intersection,element,perpendicular,infinity,proportional,congruent,\
therefore,product,summation,afii61289,partialdiff,circlemultiply,\
weierstrass,notsubset,angle,propersuperset,propersubset,reflexsuperset,\
reflexsubset,notelement,arrowdblleft,arrowdblright,arrowdblboth,\
underscoredbl,uni203E,emptyset,exclamdbl,H18543,H18551,orthogonal,\
minute,second,house,uni2126,asteriskmath,suchthat,estimated,triagrt,\
triaglf,musicalnotedbl,\
uni211E,uni2295,uni20AF,uni20DD,uni210F,uni2112,uni2120,uni2128,\
uni212D,uni212F,uni2136,uni2137,uni2196,uni2197,uni2198,uni2199,\
uni21C4,uni21C6,uni21D5,uni220D,uni2213,uni2223,uni2225,uni2227,\
uni2228,uni222E,uni2235,uni2237,uni2262,uni226A,uni226B,uni2285,\
uni2296,uni2298,uni2299,uni22A2,uni22A3,uni22A4,uni22BB,uni256D,\
uni256E,uni256F,uni2570,uni25B5,uni25B9,uni25BF,uni25C3,uni25C6,\
uni25C7,openbullet,uni301A,uni301B

EXCL=$EXCL_PCL,$EXCL_BOX

# tx -cff +F +S +T -b -n -gx $EXCL -a $f

for f in *.t1; do tx -cff +F +S +T -b -n -gx $EXCL -a $f; done
#for f in *.cff; do tx -pdf -a $f; done
