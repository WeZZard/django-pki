from cryptography import utils
from cryptography.hazmat.primitives.asymmetric import ec


# Curve Object Identifier
#
# openssl ecparam -list_curves | awk '
# {
#   if (match($0, ":") && !match($0, "Oakley-EC2N-[[:digit:]]")) {
#     FINE_STRING=$0
#     sub("[[:space:]]+", "", FINE_STRING)
#     split(FINE_STRING, COMPONENTS, "[[:space:]]*:[[:space:]]*");
#     NAME=COMPONENTS[1]
#         DESCRIPTION=COMPONENTS[1]
#     gsub("-","_",NAME)
#     CLASS_NAME=toupper(NAME)
# 	match(NAME, "[[:alpha:]][[:digit:]][[:digit:]][[:digit:]][[:alpha:]]")
# 	BITS=substr(NAME, RSTART+1, RLENGTH-2)
# 	if (length(BITS)==0) {
# 	  print "\
# 	@utils.register_interface(ec.EllipticCurve)\
# 	class "CLASS_NAME"(object):\
# 		name = \""NAME"\""
# 	} else {
# 	  print "\
# 	@utils.register_interface(ec.EllipticCurve)\
# 	class "CLASS_NAME"(object):\
# 		name = \""NAME"\"\
# 		key_size = "BITS
# 	}
#   }
# }'
#
@utils.register_interface(ec.EllipticCurve)
class SECP112R1(object):
    name = "secp112r1"
    key_size = 112


@utils.register_interface(ec.EllipticCurve)
class SECP112R2(object):
    name = "secp112r2"
    key_size = 112


@utils.register_interface(ec.EllipticCurve)
class SECP128R1(object):
    name = "secp128r1"
    key_size = 128


@utils.register_interface(ec.EllipticCurve)
class SECP128R2(object):
    name = "secp128r2"
    key_size = 128


@utils.register_interface(ec.EllipticCurve)
class SECP160K1(object):
    name = "secp160k1"
    key_size = 160


@utils.register_interface(ec.EllipticCurve)
class SECP160R1(object):
    name = "secp160r1"
    key_size = 160


@utils.register_interface(ec.EllipticCurve)
class SECP160R2(object):
    name = "secp160r2"
    key_size = 160


@utils.register_interface(ec.EllipticCurve)
class SECP192K1(object):
    name = "secp192k1"
    key_size = 192


@utils.register_interface(ec.EllipticCurve)
class SECP224K1(object):
    name = "secp224k1"
    key_size = 224


@utils.register_interface(ec.EllipticCurve)
class SECP224R1(object):
    name = "secp224r1"
    key_size = 224


@utils.register_interface(ec.EllipticCurve)
class SECP256K1(object):
    name = "secp256k1"
    key_size = 256


@utils.register_interface(ec.EllipticCurve)
class SECP384R1(object):
    name = "secp384r1"
    key_size = 384


@utils.register_interface(ec.EllipticCurve)
class SECP521R1(object):
    name = "secp521r1"
    key_size = 521


@utils.register_interface(ec.EllipticCurve)
class PRIME192V1(object):
    name = "prime192v1"
    key_size = 192


@utils.register_interface(ec.EllipticCurve)
class PRIME192V2(object):
    name = "prime192v2"
    key_size = 192


@utils.register_interface(ec.EllipticCurve)
class PRIME192V3(object):
    name = "prime192v3"
    key_size = 192


@utils.register_interface(ec.EllipticCurve)
class PRIME239V1(object):
    name = "prime239v1"
    key_size = 239


@utils.register_interface(ec.EllipticCurve)
class PRIME239V2(object):
    name = "prime239v2"
    key_size = 239


@utils.register_interface(ec.EllipticCurve)
class PRIME239V3(object):
    name = "prime239v3"
    key_size = 239


@utils.register_interface(ec.EllipticCurve)
class PRIME256V1(object):
    name = "prime256v1"
    key_size = 256


@utils.register_interface(ec.EllipticCurve)
class SECT113R1(object):
    name = "sect113r1"
    key_size = 113


@utils.register_interface(ec.EllipticCurve)
class SECT113R2(object):
    name = "sect113r2"
    key_size = 113


@utils.register_interface(ec.EllipticCurve)
class SECT131R1(object):
    name = "sect131r1"
    key_size = 131


@utils.register_interface(ec.EllipticCurve)
class SECT131R2(object):
    name = "sect131r2"
    key_size = 131


@utils.register_interface(ec.EllipticCurve)
class SECT163K1(object):
    name = "sect163k1"
    key_size = 163


@utils.register_interface(ec.EllipticCurve)
class SECT163R1(object):
    name = "sect163r1"
    key_size = 163


@utils.register_interface(ec.EllipticCurve)
class SECT163R2(object):
    name = "sect163r2"
    key_size = 163


@utils.register_interface(ec.EllipticCurve)
class SECT193R1(object):
    name = "sect193r1"
    key_size = 193


@utils.register_interface(ec.EllipticCurve)
class SECT193R2(object):
    name = "sect193r2"
    key_size = 193


@utils.register_interface(ec.EllipticCurve)
class SECT233K1(object):
    name = "sect233k1"
    key_size = 233


@utils.register_interface(ec.EllipticCurve)
class SECT233R1(object):
    name = "sect233r1"
    key_size = 233


@utils.register_interface(ec.EllipticCurve)
class SECT239K1(object):
    name = "sect239k1"
    key_size = 239


@utils.register_interface(ec.EllipticCurve)
class SECT283K1(object):
    name = "sect283k1"
    key_size = 283


@utils.register_interface(ec.EllipticCurve)
class SECT283R1(object):
    name = "sect283r1"
    key_size = 283


@utils.register_interface(ec.EllipticCurve)
class SECT409K1(object):
    name = "sect409k1"
    key_size = 409


@utils.register_interface(ec.EllipticCurve)
class SECT409R1(object):
    name = "sect409r1"
    key_size = 409


@utils.register_interface(ec.EllipticCurve)
class SECT571K1(object):
    name = "sect571k1"
    key_size = 571


@utils.register_interface(ec.EllipticCurve)
class SECT571R1(object):
    name = "sect571r1"
    key_size = 571


@utils.register_interface(ec.EllipticCurve)
class C2PNB163V1(object):
    name = "c2pnb163v1"
    key_size = 163


@utils.register_interface(ec.EllipticCurve)
class C2PNB163V2(object):
    name = "c2pnb163v2"
    key_size = 163


@utils.register_interface(ec.EllipticCurve)
class C2PNB163V3(object):
    name = "c2pnb163v3"
    key_size = 163


@utils.register_interface(ec.EllipticCurve)
class C2PNB176V1(object):
    name = "c2pnb176v1"
    key_size = 176


@utils.register_interface(ec.EllipticCurve)
class C2TNB191V1(object):
    name = "c2tnb191v1"
    key_size = 191


@utils.register_interface(ec.EllipticCurve)
class C2TNB191V2(object):
    name = "c2tnb191v2"
    key_size = 191


@utils.register_interface(ec.EllipticCurve)
class C2TNB191V3(object):
    name = "c2tnb191v3"
    key_size = 191


@utils.register_interface(ec.EllipticCurve)
class C2PNB208W1(object):
    name = "c2pnb208w1"
    key_size = 208


@utils.register_interface(ec.EllipticCurve)
class C2TNB239V1(object):
    name = "c2tnb239v1"
    key_size = 239


@utils.register_interface(ec.EllipticCurve)
class C2TNB239V2(object):
    name = "c2tnb239v2"
    key_size = 239


@utils.register_interface(ec.EllipticCurve)
class C2TNB239V3(object):
    name = "c2tnb239v3"
    key_size = 239


@utils.register_interface(ec.EllipticCurve)
class C2PNB272W1(object):
    name = "c2pnb272w1"
    key_size = 272


@utils.register_interface(ec.EllipticCurve)
class C2PNB304W1(object):
    name = "c2pnb304w1"
    key_size = 304


@utils.register_interface(ec.EllipticCurve)
class C2TNB359V1(object):
    name = "c2tnb359v1"
    key_size = 359


@utils.register_interface(ec.EllipticCurve)
class C2PNB368W1(object):
    name = "c2pnb368w1"
    key_size = 368


@utils.register_interface(ec.EllipticCurve)
class C2TNB431R1(object):
    name = "c2tnb431r1"
    key_size = 431


@utils.register_interface(ec.EllipticCurve)
class WAP_WSG_IDM_ECID_WTLS1(object):
    name = "wap_wsg_idm_ecid_wtls1"
    key_size = None


@utils.register_interface(ec.EllipticCurve)
class WAP_WSG_IDM_ECID_WTLS3(object):
    name = "wap_wsg_idm_ecid_wtls3"
    key_size = None


@utils.register_interface(ec.EllipticCurve)
class WAP_WSG_IDM_ECID_WTLS4(object):
    name = "wap_wsg_idm_ecid_wtls4"
    key_size = None


@utils.register_interface(ec.EllipticCurve)
class WAP_WSG_IDM_ECID_WTLS5(object):
    name = "wap_wsg_idm_ecid_wtls5"
    key_size = None


@utils.register_interface(ec.EllipticCurve)
class WAP_WSG_IDM_ECID_WTLS6(object):
    name = "wap_wsg_idm_ecid_wtls6"
    key_size = None


@utils.register_interface(ec.EllipticCurve)
class WAP_WSG_IDM_ECID_WTLS7(object):
    name = "wap_wsg_idm_ecid_wtls7"
    key_size = None


@utils.register_interface(ec.EllipticCurve)
class WAP_WSG_IDM_ECID_WTLS8(object):
    name = "wap_wsg_idm_ecid_wtls8"
    key_size = None


@utils.register_interface(ec.EllipticCurve)
class WAP_WSG_IDM_ECID_WTLS9(object):
    name = "wap_wsg_idm_ecid_wtls9"
    key_size = None


@utils.register_interface(ec.EllipticCurve)
class WAP_WSG_IDM_ECID_WTLS10(object):
    name = "wap_wsg_idm_ecid_wtls10"
    key_size = None


@utils.register_interface(ec.EllipticCurve)
class WAP_WSG_IDM_ECID_WTLS11(object):
    name = "wap_wsg_idm_ecid_wtls11"
    key_size = None


@utils.register_interface(ec.EllipticCurve)
class WAP_WSG_IDM_ECID_WTLS12(object):
    name = "wap_wsg_idm_ecid_wtls12"
    key_size = None


@utils.register_interface(ec.EllipticCurve)
class BRAINPOOLP160R1(object):
    name = "brainpoolP160r1"
    key_size = 160


@utils.register_interface(ec.EllipticCurve)
class BRAINPOOLP160T1(object):
    name = "brainpoolP160t1"
    key_size = 160


@utils.register_interface(ec.EllipticCurve)
class BRAINPOOLP192R1(object):
    name = "brainpoolP192r1"
    key_size = 192


@utils.register_interface(ec.EllipticCurve)
class BRAINPOOLP192T1(object):
    name = "brainpoolP192t1"
    key_size = 192


@utils.register_interface(ec.EllipticCurve)
class BRAINPOOLP224R1(object):
    name = "brainpoolP224r1"
    key_size = 224


@utils.register_interface(ec.EllipticCurve)
class BRAINPOOLP224T1(object):
    name = "brainpoolP224t1"
    key_size = 224


@utils.register_interface(ec.EllipticCurve)
class BRAINPOOLP256R1(object):
    name = "brainpoolP256r1"
    key_size = 256


@utils.register_interface(ec.EllipticCurve)
class BRAINPOOLP256T1(object):
    name = "brainpoolP256t1"
    key_size = 256


@utils.register_interface(ec.EllipticCurve)
class BRAINPOOLP320R1(object):
    name = "brainpoolP320r1"
    key_size = 320


@utils.register_interface(ec.EllipticCurve)
class BRAINPOOLP320T1(object):
    name = "brainpoolP320t1"
    key_size = 320


@utils.register_interface(ec.EllipticCurve)
class BRAINPOOLP384R1(object):
    name = "brainpoolP384r1"
    key_size = 384


@utils.register_interface(ec.EllipticCurve)
class BRAINPOOLP384T1(object):
    name = "brainpoolP384t1"
    key_size = 384


@utils.register_interface(ec.EllipticCurve)
class BRAINPOOLP512R1(object):
    name = "brainpoolP512r1"
    key_size = 512


@utils.register_interface(ec.EllipticCurve)
class BRAINPOOLP512T1(object):
    name = "brainpoolP512t1"
    key_size = 512


@utils.register_interface(ec.EllipticCurve)
class FRP256V1(object):
    name = "FRP256v1"
    key_size = 256


@utils.register_interface(ec.EllipticCurve)
class ID_GOSTR3410_2001_TESTPARAMSET(object):
    name = "id_GostR3410_2001_TestParamSet"
    key_size = None


@utils.register_interface(ec.EllipticCurve)
class ID_GOSTR3410_2001_CRYPTOPRO_A_PARAMSET(object):
    name = "id_GostR3410_2001_CryptoPro_A_ParamSet"
    key_size = None


@utils.register_interface(ec.EllipticCurve)
class ID_GOSTR3410_2001_CRYPTOPRO_B_PARAMSET(object):
    name = "id_GostR3410_2001_CryptoPro_B_ParamSet"
    key_size = None


@utils.register_interface(ec.EllipticCurve)
class ID_GOSTR3410_2001_CRYPTOPRO_C_PARAMSET(object):
    name = "id_GostR3410_2001_CryptoPro_C_ParamSet"
    key_size = None


@utils.register_interface(ec.EllipticCurve)
class ID_GOSTR3410_2001_CRYPTOPRO_XCHA_PARAMSET(object):
    name = "id_GostR3410_2001_CryptoPro_XchA_ParamSet"
    key_size = None


@utils.register_interface(ec.EllipticCurve)
class ID_GOSTR3410_2001_CRYPTOPRO_XCHB_PARAMSET(object):
    name = "id_GostR3410_2001_CryptoPro_XchB_ParamSet"
    key_size = None


@utils.register_interface(ec.EllipticCurve)
class ID_TC26_GOST_3410_2012_512_PARAMSETA(object):
    name = "id_tc26_gost_3410_2012_512_paramSetA"
    key_size = None


@utils.register_interface(ec.EllipticCurve)
class ID_TC26_GOST_3410_2012_512_PARAMSETB(object):
    name = "id_tc26_gost_3410_2012_512_paramSetB"
    key_size = None
