from typing import List
from typing import Optional
from typing import Type

from enumfields import Enum

from ..common.elliptic_curve_oids import *

# Shell script generates the members
#
# openssl ecparam -list_curves | awk '
# {
#   if (match($0, ":") && !match($0, "Oakley-EC2N-[[:digit:]]")) {
#     FINE_STRING=$0
#     sub("[[:space:]]+", "", FINE_STRING)
#     split(FINE_STRING, COMPONENTS, "[[:space:]]*:[[:space:]]*");
#     NAME=COMPONENTS[1]
#     VALUE=COMPONENTS[1]
#     gsub("-","_",NAME)
#     NAME=toupper(NAME)
#     print NAME" = \""VALUE"\""
#   }
# }'
#
class EllipticCurve(Enum):
    SECP112R1 = "secp112r1"
    SECP112R2 = "secp112r2"
    SECP128R1 = "secp128r1"
    SECP128R2 = "secp128r2"
    SECP160K1 = "secp160k1"
    SECP160R1 = "secp160r1"
    SECP160R2 = "secp160r2"
    SECP192K1 = "secp192k1"
    SECP224K1 = "secp224k1"
    SECP224R1 = "secp224r1"
    SECP256K1 = "secp256k1"
    SECP384R1 = "secp384r1"
    SECP521R1 = "secp521r1"
    PRIME192V1 = "prime192v1"
    PRIME192V2 = "prime192v2"
    PRIME192V3 = "prime192v3"
    PRIME239V1 = "prime239v1"
    PRIME239V2 = "prime239v2"
    PRIME239V3 = "prime239v3"
    PRIME256V1 = "prime256v1"
    SECT113R1 = "sect113r1"
    SECT113R2 = "sect113r2"
    SECT131R1 = "sect131r1"
    SECT131R2 = "sect131r2"
    SECT163K1 = "sect163k1"
    SECT163R1 = "sect163r1"
    SECT163R2 = "sect163r2"
    SECT193R1 = "sect193r1"
    SECT193R2 = "sect193r2"
    SECT233K1 = "sect233k1"
    SECT233R1 = "sect233r1"
    SECT239K1 = "sect239k1"
    SECT283K1 = "sect283k1"
    SECT283R1 = "sect283r1"
    SECT409K1 = "sect409k1"
    SECT409R1 = "sect409r1"
    SECT571K1 = "sect571k1"
    SECT571R1 = "sect571r1"
    C2PNB163V1 = "c2pnb163v1"
    C2PNB163V2 = "c2pnb163v2"
    C2PNB163V3 = "c2pnb163v3"
    C2PNB176V1 = "c2pnb176v1"
    C2TNB191V1 = "c2tnb191v1"
    C2TNB191V2 = "c2tnb191v2"
    C2TNB191V3 = "c2tnb191v3"
    C2PNB208W1 = "c2pnb208w1"
    C2TNB239V1 = "c2tnb239v1"
    C2TNB239V2 = "c2tnb239v2"
    C2TNB239V3 = "c2tnb239v3"
    C2PNB272W1 = "c2pnb272w1"
    C2PNB304W1 = "c2pnb304w1"
    C2TNB359V1 = "c2tnb359v1"
    C2PNB368W1 = "c2pnb368w1"
    C2TNB431R1 = "c2tnb431r1"
    WAP_WSG_IDM_ECID_WTLS1 = "wap-wsg-idm-ecid-wtls1"
    WAP_WSG_IDM_ECID_WTLS3 = "wap-wsg-idm-ecid-wtls3"
    WAP_WSG_IDM_ECID_WTLS4 = "wap-wsg-idm-ecid-wtls4"
    WAP_WSG_IDM_ECID_WTLS5 = "wap-wsg-idm-ecid-wtls5"
    WAP_WSG_IDM_ECID_WTLS6 = "wap-wsg-idm-ecid-wtls6"
    WAP_WSG_IDM_ECID_WTLS7 = "wap-wsg-idm-ecid-wtls7"
    WAP_WSG_IDM_ECID_WTLS8 = "wap-wsg-idm-ecid-wtls8"
    WAP_WSG_IDM_ECID_WTLS9 = "wap-wsg-idm-ecid-wtls9"
    WAP_WSG_IDM_ECID_WTLS10 = "wap-wsg-idm-ecid-wtls10"
    WAP_WSG_IDM_ECID_WTLS11 = "wap-wsg-idm-ecid-wtls11"
    WAP_WSG_IDM_ECID_WTLS12 = "wap-wsg-idm-ecid-wtls12"
    BRAINPOOLP160R1 = "brainpoolP160r1"
    BRAINPOOLP160T1 = "brainpoolP160t1"
    BRAINPOOLP192R1 = "brainpoolP192r1"
    BRAINPOOLP192T1 = "brainpoolP192t1"
    BRAINPOOLP224R1 = "brainpoolP224r1"
    BRAINPOOLP224T1 = "brainpoolP224t1"
    BRAINPOOLP256R1 = "brainpoolP256r1"
    BRAINPOOLP256T1 = "brainpoolP256t1"
    BRAINPOOLP320R1 = "brainpoolP320r1"
    BRAINPOOLP320T1 = "brainpoolP320t1"
    BRAINPOOLP384R1 = "brainpoolP384r1"
    BRAINPOOLP384T1 = "brainpoolP384t1"
    BRAINPOOLP512R1 = "brainpoolP512r1"
    BRAINPOOLP512T1 = "brainpoolP512t1"
    FRP256V1 = "FRP256v1"
    ID_GOSTR3410_2001_TESTPARAMSET = "id-GostR3410-2001-TestParamSet"
    ID_GOSTR3410_2001_CRYPTOPRO_A_PARAMSET = "id-GostR3410-2001-CryptoPro-A-ParamSet"
    ID_GOSTR3410_2001_CRYPTOPRO_B_PARAMSET = "id-GostR3410-2001-CryptoPro-B-ParamSet"
    ID_GOSTR3410_2001_CRYPTOPRO_C_PARAMSET = "id-GostR3410-2001-CryptoPro-C-ParamSet"
    ID_GOSTR3410_2001_CRYPTOPRO_XCHA_PARAMSET = "id-GostR3410-2001-CryptoPro-XchA-ParamSet"
    ID_GOSTR3410_2001_CRYPTOPRO_XCHB_PARAMSET = "id-GostR3410-2001-CryptoPro-XchB-ParamSet"
    ID_TC26_GOST_3410_2012_512_PARAMSETA = "id-tc26-gost-3410-2012-512-paramSetA"
    ID_TC26_GOST_3410_2012_512_PARAMSETB = "id-tc26-gost-3410-2012-512-paramSetB"

    @property
    def name(self) -> str:
        return self.value

    def get_oid_type(self) -> Type[object]:
        if self == EllipticCurve.SECP112R1:
            return SECP112R1
        if self == EllipticCurve.SECP112R2:
            return SECP112R2
        if self == EllipticCurve.SECP128R1:
            return SECP128R1
        if self == EllipticCurve.SECP128R2:
            return SECP128R2
        if self == EllipticCurve.SECP160K1:
            return SECP160K1
        if self == EllipticCurve.SECP160R1:
            return SECP160R1
        if self == EllipticCurve.SECP160R2:
            return SECP160R2
        if self == EllipticCurve.SECP192K1:
            return SECP192K1
        if self == EllipticCurve.SECP224K1:
            return SECP224K1
        if self == EllipticCurve.SECP224R1:
            return SECP224R1
        if self == EllipticCurve.SECP256K1:
            return SECP256K1
        if self == EllipticCurve.SECP384R1:
            return SECP384R1
        if self == EllipticCurve.SECP521R1:
            return SECP521R1
        if self == EllipticCurve.PRIME192V1:
            return PRIME192V1
        if self == EllipticCurve.PRIME192V2:
            return PRIME192V2
        if self == EllipticCurve.PRIME192V3:
            return PRIME192V3
        if self == EllipticCurve.PRIME239V1:
            return PRIME239V1
        if self == EllipticCurve.PRIME239V2:
            return PRIME239V2
        if self == EllipticCurve.PRIME239V3:
            return PRIME239V3
        if self == EllipticCurve.PRIME256V1:
            return PRIME256V1
        if self == EllipticCurve.SECT113R1:
            return SECT113R1
        if self == EllipticCurve.SECT113R2:
            return SECT113R2
        if self == EllipticCurve.SECT131R1:
            return SECT131R1
        if self == EllipticCurve.SECT131R2:
            return SECT131R2
        if self == EllipticCurve.SECT163K1:
            return SECT163K1
        if self == EllipticCurve.SECT163R1:
            return SECT163R1
        if self == EllipticCurve.SECT163R2:
            return SECT163R2
        if self == EllipticCurve.SECT193R1:
            return SECT193R1
        if self == EllipticCurve.SECT193R2:
            return SECT193R2
        if self == EllipticCurve.SECT233K1:
            return SECT233K1
        if self == EllipticCurve.SECT233R1:
            return SECT233R1
        if self == EllipticCurve.SECT239K1:
            return SECT239K1
        if self == EllipticCurve.SECT283K1:
            return SECT283K1
        if self == EllipticCurve.SECT283R1:
            return SECT283R1
        if self == EllipticCurve.SECT409K1:
            return SECT409K1
        if self == EllipticCurve.SECT409R1:
            return SECT409R1
        if self == EllipticCurve.SECT571K1:
            return SECT571K1
        if self == EllipticCurve.SECT571R1:
            return SECT571R1
        if self == EllipticCurve.C2PNB163V1:
            return C2PNB163V1
        if self == EllipticCurve.C2PNB163V2:
            return C2PNB163V2
        if self == EllipticCurve.C2PNB163V3:
            return C2PNB163V3
        if self == EllipticCurve.C2PNB176V1:
            return C2PNB176V1
        if self == EllipticCurve.C2TNB191V1:
            return C2TNB191V1
        if self == EllipticCurve.C2TNB191V2:
            return C2TNB191V2
        if self == EllipticCurve.C2TNB191V3:
            return C2TNB191V3
        if self == EllipticCurve.C2PNB208W1:
            return C2PNB208W1
        if self == EllipticCurve.C2TNB239V1:
            return C2TNB239V1
        if self == EllipticCurve.C2TNB239V2:
            return C2TNB239V2
        if self == EllipticCurve.C2TNB239V3:
            return C2TNB239V3
        if self == EllipticCurve.C2PNB272W1:
            return C2PNB272W1
        if self == EllipticCurve.C2PNB304W1:
            return C2PNB304W1
        if self == EllipticCurve.C2TNB359V1:
            return C2TNB359V1
        if self == EllipticCurve.C2PNB368W1:
            return C2PNB368W1
        if self == EllipticCurve.C2TNB431R1:
            return C2TNB431R1
        if self == EllipticCurve.WAP_WSG_IDM_ECID_WTLS1:
            return WAP_WSG_IDM_ECID_WTLS1
        if self == EllipticCurve.WAP_WSG_IDM_ECID_WTLS3:
            return WAP_WSG_IDM_ECID_WTLS3
        if self == EllipticCurve.WAP_WSG_IDM_ECID_WTLS4:
            return WAP_WSG_IDM_ECID_WTLS4
        if self == EllipticCurve.WAP_WSG_IDM_ECID_WTLS5:
            return WAP_WSG_IDM_ECID_WTLS5
        if self == EllipticCurve.WAP_WSG_IDM_ECID_WTLS6:
            return WAP_WSG_IDM_ECID_WTLS6
        if self == EllipticCurve.WAP_WSG_IDM_ECID_WTLS7:
            return WAP_WSG_IDM_ECID_WTLS7
        if self == EllipticCurve.WAP_WSG_IDM_ECID_WTLS8:
            return WAP_WSG_IDM_ECID_WTLS8
        if self == EllipticCurve.WAP_WSG_IDM_ECID_WTLS9:
            return WAP_WSG_IDM_ECID_WTLS9
        if self == EllipticCurve.WAP_WSG_IDM_ECID_WTLS10:
            return WAP_WSG_IDM_ECID_WTLS10
        if self == EllipticCurve.WAP_WSG_IDM_ECID_WTLS11:
            return WAP_WSG_IDM_ECID_WTLS11
        if self == EllipticCurve.WAP_WSG_IDM_ECID_WTLS12:
            return WAP_WSG_IDM_ECID_WTLS12
        if self == EllipticCurve.BRAINPOOLP160R1:
            return BRAINPOOLP160R1
        if self == EllipticCurve.BRAINPOOLP160T1:
            return BRAINPOOLP160T1
        if self == EllipticCurve.BRAINPOOLP192R1:
            return BRAINPOOLP192R1
        if self == EllipticCurve.BRAINPOOLP192T1:
            return BRAINPOOLP192T1
        if self == EllipticCurve.BRAINPOOLP224R1:
            return BRAINPOOLP224R1
        if self == EllipticCurve.BRAINPOOLP224T1:
            return BRAINPOOLP224T1
        if self == EllipticCurve.BRAINPOOLP256R1:
            return BRAINPOOLP256R1
        if self == EllipticCurve.BRAINPOOLP256T1:
            return BRAINPOOLP256T1
        if self == EllipticCurve.BRAINPOOLP320R1:
            return BRAINPOOLP320R1
        if self == EllipticCurve.BRAINPOOLP320T1:
            return BRAINPOOLP320T1
        if self == EllipticCurve.BRAINPOOLP384R1:
            return BRAINPOOLP384R1
        if self == EllipticCurve.BRAINPOOLP384T1:
            return BRAINPOOLP384T1
        if self == EllipticCurve.BRAINPOOLP512R1:
            return BRAINPOOLP512R1
        if self == EllipticCurve.BRAINPOOLP512T1:
            return BRAINPOOLP512T1
        if self == EllipticCurve.FRP256V1:
            return FRP256V1
        if self == EllipticCurve.ID_GOSTR3410_2001_TESTPARAMSET:
            return ID_GOSTR3410_2001_TESTPARAMSET
        if self == EllipticCurve.ID_GOSTR3410_2001_CRYPTOPRO_A_PARAMSET:
            return ID_GOSTR3410_2001_CRYPTOPRO_A_PARAMSET
        if self == EllipticCurve.ID_GOSTR3410_2001_CRYPTOPRO_B_PARAMSET:
            return ID_GOSTR3410_2001_CRYPTOPRO_B_PARAMSET
        if self == EllipticCurve.ID_GOSTR3410_2001_CRYPTOPRO_C_PARAMSET:
            return ID_GOSTR3410_2001_CRYPTOPRO_C_PARAMSET
        if self == EllipticCurve.ID_GOSTR3410_2001_CRYPTOPRO_XCHA_PARAMSET:
            return ID_GOSTR3410_2001_CRYPTOPRO_XCHA_PARAMSET
        if self == EllipticCurve.ID_GOSTR3410_2001_CRYPTOPRO_XCHB_PARAMSET:
            return ID_GOSTR3410_2001_CRYPTOPRO_XCHB_PARAMSET
        if self == EllipticCurve.ID_TC26_GOST_3410_2012_512_PARAMSETA:
            return ID_TC26_GOST_3410_2012_512_PARAMSETA
        if self == EllipticCurve.ID_TC26_GOST_3410_2012_512_PARAMSETB:
            return ID_TC26_GOST_3410_2012_512_PARAMSETB
        raise ValueError()

    # Shell script generates the function body
    #
    # openssl ecparam -list_curves | awk '
    # BEGIN {
    #   ENVIRON[CHOICES]=""
    # }
    # {
    #   if (match($0, ":") && !match($0, "Oakley-EC2N-[[:digit:]]")) {
    #     FINE_STRING=$0
    #     sub("[[:space:]]+", "", FINE_STRING)
    #     split(FINE_STRING, COMPONENTS, "[[:space:]]*:[[:space:]]*");
    #     NAME=COMPONENTS[1]
    #     gsub("-","_",NAME)
    #     NAME=toupper(NAME)
    # 	if (length(ENVIRON[CHOICES]) == 0) {
    #       ENVIRON[CHOICES]="EllipticCurve."NAME
    # 	} else {
    #       ENVIRON[CHOICES]=ENVIRON[CHOICES]", EllipticCurve."NAME
    # 	}
    #   }
    # }
    # END {
    #   print "return \["ENVIRON[CHOICES]"\]"
    # }
    # '
    @classmethod
    def get_all_elliptic_curves(cls) -> List['EllipticCurve']:
        return [EllipticCurve.SECP112R1, EllipticCurve.SECP112R2,
                EllipticCurve.SECP128R1, EllipticCurve.SECP128R2,
                EllipticCurve.SECP160K1, EllipticCurve.SECP160R1,
                EllipticCurve.SECP160R2, EllipticCurve.SECP192K1,
                EllipticCurve.SECP224K1, EllipticCurve.SECP224R1,
                EllipticCurve.SECP256K1, EllipticCurve.SECP384R1,
                EllipticCurve.SECP521R1, EllipticCurve.PRIME192V1,
                EllipticCurve.PRIME192V2, EllipticCurve.PRIME192V3,
                EllipticCurve.PRIME239V1, EllipticCurve.PRIME239V2,
                EllipticCurve.PRIME239V3, EllipticCurve.PRIME256V1,
                EllipticCurve.SECT113R1, EllipticCurve.SECT113R2,
                EllipticCurve.SECT131R1, EllipticCurve.SECT131R2,
                EllipticCurve.SECT163K1, EllipticCurve.SECT163R1,
                EllipticCurve.SECT163R2, EllipticCurve.SECT193R1,
                EllipticCurve.SECT193R2, EllipticCurve.SECT233K1,
                EllipticCurve.SECT233R1, EllipticCurve.SECT239K1,
                EllipticCurve.SECT283K1, EllipticCurve.SECT283R1,
                EllipticCurve.SECT409K1, EllipticCurve.SECT409R1,
                EllipticCurve.SECT571K1, EllipticCurve.SECT571R1,
                EllipticCurve.C2PNB163V1, EllipticCurve.C2PNB163V2,
                EllipticCurve.C2PNB163V3, EllipticCurve.C2PNB176V1,
                EllipticCurve.C2TNB191V1, EllipticCurve.C2TNB191V2,
                EllipticCurve.C2TNB191V3, EllipticCurve.C2PNB208W1,
                EllipticCurve.C2TNB239V1, EllipticCurve.C2TNB239V2,
                EllipticCurve.C2TNB239V3, EllipticCurve.C2PNB272W1,
                EllipticCurve.C2PNB304W1, EllipticCurve.C2TNB359V1,
                EllipticCurve.C2PNB368W1, EllipticCurve.C2TNB431R1,
                EllipticCurve.WAP_WSG_IDM_ECID_WTLS1,
                EllipticCurve.WAP_WSG_IDM_ECID_WTLS3,
                EllipticCurve.WAP_WSG_IDM_ECID_WTLS4,
                EllipticCurve.WAP_WSG_IDM_ECID_WTLS5,
                EllipticCurve.WAP_WSG_IDM_ECID_WTLS6,
                EllipticCurve.WAP_WSG_IDM_ECID_WTLS7,
                EllipticCurve.WAP_WSG_IDM_ECID_WTLS8,
                EllipticCurve.WAP_WSG_IDM_ECID_WTLS9,
                EllipticCurve.WAP_WSG_IDM_ECID_WTLS10,
                EllipticCurve.WAP_WSG_IDM_ECID_WTLS11,
                EllipticCurve.WAP_WSG_IDM_ECID_WTLS12,
                EllipticCurve.BRAINPOOLP160R1, EllipticCurve.BRAINPOOLP160T1,
                EllipticCurve.BRAINPOOLP192R1, EllipticCurve.BRAINPOOLP192T1,
                EllipticCurve.BRAINPOOLP224R1, EllipticCurve.BRAINPOOLP224T1,
                EllipticCurve.BRAINPOOLP256R1, EllipticCurve.BRAINPOOLP256T1,
                EllipticCurve.BRAINPOOLP320R1, EllipticCurve.BRAINPOOLP320T1,
                EllipticCurve.BRAINPOOLP384R1, EllipticCurve.BRAINPOOLP384T1,
                EllipticCurve.BRAINPOOLP512R1, EllipticCurve.BRAINPOOLP512T1,
                EllipticCurve.FRP256V1,
                EllipticCurve.ID_GOSTR3410_2001_TESTPARAMSET,
                EllipticCurve.ID_GOSTR3410_2001_CRYPTOPRO_A_PARAMSET,
                EllipticCurve.ID_GOSTR3410_2001_CRYPTOPRO_B_PARAMSET,
                EllipticCurve.ID_GOSTR3410_2001_CRYPTOPRO_C_PARAMSET,
                EllipticCurve.ID_GOSTR3410_2001_CRYPTOPRO_XCHA_PARAMSET,
                EllipticCurve.ID_GOSTR3410_2001_CRYPTOPRO_XCHB_PARAMSET,
                EllipticCurve.ID_TC26_GOST_3410_2012_512_PARAMSETA,
                EllipticCurve.ID_TC26_GOST_3410_2012_512_PARAMSETB]

    @classmethod
    def get_available_elliptic_curves(cls) -> List['EllipticCurve']:
        from cryptography.hazmat.backends import default_backend
        backend = default_backend()
        return list(filter(
            lambda x: backend.elliptic_curve_supported(x.get_oid_type()()),
            cls.get_all_elliptic_curves()
        ))

    # Shell script generates the members
    #
    # openssl ecparam -list_curves | awk '
    # {
    #   if (match($0, ":") && !match($0, "Oakley-EC2N-[[:digit:]]")) {
    #     FINE_STRING=$0
    #     sub("[[:space:]]+", "", FINE_STRING)
    #     split(FINE_STRING, COMPONENTS, "[[:space:]]*:[[:space:]]*");
    #     NAME=COMPONENTS[1]
    #     VALUE=COMPONENTS[1]
    #     gsub("-","_",NAME)
    #     NAME=toupper(NAME)
    #     print NAME" = \""VALUE": "COMPONENTS[2]"\""
    #   }
    # }'
    #
    class Labels:
        SECP112R1 = "secp112r1: SECG/WTLS curve over a 112 bit prime field"
        SECP112R2 = "secp112r2: SECG curve over a 112 bit prime field"
        SECP128R1 = "secp128r1: SECG curve over a 128 bit prime field"
        SECP128R2 = "secp128r2: SECG curve over a 128 bit prime field"
        SECP160K1 = "secp160k1: SECG curve over a 160 bit prime field"
        SECP160R1 = "secp160r1: SECG curve over a 160 bit prime field"
        SECP160R2 = "secp160r2: SECG/WTLS curve over a 160 bit prime field"
        SECP192K1 = "secp192k1: SECG curve over a 192 bit prime field"
        SECP224K1 = "secp224k1: SECG curve over a 224 bit prime field"
        SECP224R1 = "secp224r1: NIST/SECG curve over a 224 bit prime field"
        SECP256K1 = "secp256k1: SECG curve over a 256 bit prime field"
        SECP384R1 = "secp384r1: NIST/SECG curve over a 384 bit prime field"
        SECP521R1 = "secp521r1: NIST/SECG curve over a 521 bit prime field"
        PRIME192V1 = "prime192v1: NIST/X9.62/SECG curve over a 192 bit prime field"
        PRIME192V2 = "prime192v2: X9.62 curve over a 192 bit prime field"
        PRIME192V3 = "prime192v3: X9.62 curve over a 192 bit prime field"
        PRIME239V1 = "prime239v1: X9.62 curve over a 239 bit prime field"
        PRIME239V2 = "prime239v2: X9.62 curve over a 239 bit prime field"
        PRIME239V3 = "prime239v3: X9.62 curve over a 239 bit prime field"
        PRIME256V1 = "prime256v1: X9.62/SECG curve over a 256 bit prime field"
        SECT113R1 = "sect113r1: SECG curve over a 113 bit binary field"
        SECT113R2 = "sect113r2: SECG curve over a 113 bit binary field"
        SECT131R1 = "sect131r1: SECG/WTLS curve over a 131 bit binary field"
        SECT131R2 = "sect131r2: SECG curve over a 131 bit binary field"
        SECT163K1 = "sect163k1: NIST/SECG/WTLS curve over a 163 bit binary field"
        SECT163R1 = "sect163r1: SECG curve over a 163 bit binary field"
        SECT163R2 = "sect163r2: NIST/SECG curve over a 163 bit binary field"
        SECT193R1 = "sect193r1: SECG curve over a 193 bit binary field"
        SECT193R2 = "sect193r2: SECG curve over a 193 bit binary field"
        SECT233K1 = "sect233k1: NIST/SECG/WTLS curve over a 233 bit binary field"
        SECT233R1 = "sect233r1: NIST/SECG/WTLS curve over a 233 bit binary field"
        SECT239K1 = "sect239k1: SECG curve over a 239 bit binary field"
        SECT283K1 = "sect283k1: NIST/SECG curve over a 283 bit binary field"
        SECT283R1 = "sect283r1: NIST/SECG curve over a 283 bit binary field"
        SECT409K1 = "sect409k1: NIST/SECG curve over a 409 bit binary field"
        SECT409R1 = "sect409r1: NIST/SECG curve over a 409 bit binary field"
        SECT571K1 = "sect571k1: NIST/SECG curve over a 571 bit binary field"
        SECT571R1 = "sect571r1: NIST/SECG curve over a 571 bit binary field"
        C2PNB163V1 = "c2pnb163v1: X9.62 curve over a 163 bit binary field"
        C2PNB163V2 = "c2pnb163v2: X9.62 curve over a 163 bit binary field"
        C2PNB163V3 = "c2pnb163v3: X9.62 curve over a 163 bit binary field"
        C2PNB176V1 = "c2pnb176v1: X9.62 curve over a 176 bit binary field"
        C2TNB191V1 = "c2tnb191v1: X9.62 curve over a 191 bit binary field"
        C2TNB191V2 = "c2tnb191v2: X9.62 curve over a 191 bit binary field"
        C2TNB191V3 = "c2tnb191v3: X9.62 curve over a 191 bit binary field"
        C2PNB208W1 = "c2pnb208w1: X9.62 curve over a 208 bit binary field"
        C2TNB239V1 = "c2tnb239v1: X9.62 curve over a 239 bit binary field"
        C2TNB239V2 = "c2tnb239v2: X9.62 curve over a 239 bit binary field"
        C2TNB239V3 = "c2tnb239v3: X9.62 curve over a 239 bit binary field"
        C2PNB272W1 = "c2pnb272w1: X9.62 curve over a 272 bit binary field"
        C2PNB304W1 = "c2pnb304w1: X9.62 curve over a 304 bit binary field"
        C2TNB359V1 = "c2tnb359v1: X9.62 curve over a 359 bit binary field"
        C2PNB368W1 = "c2pnb368w1: X9.62 curve over a 368 bit binary field"
        C2TNB431R1 = "c2tnb431r1: X9.62 curve over a 431 bit binary field"
        WAP_WSG_IDM_ECID_WTLS1 = "wap-wsg-idm-ecid-wtls1: WTLS curve over a 113 bit binary field"
        WAP_WSG_IDM_ECID_WTLS3 = "wap-wsg-idm-ecid-wtls3: NIST/SECG/WTLS curve over a 163 bit binary field"
        WAP_WSG_IDM_ECID_WTLS4 = "wap-wsg-idm-ecid-wtls4: SECG curve over a 113 bit binary field"
        WAP_WSG_IDM_ECID_WTLS5 = "wap-wsg-idm-ecid-wtls5: X9.62 curve over a 163 bit binary field"
        WAP_WSG_IDM_ECID_WTLS6 = "wap-wsg-idm-ecid-wtls6: SECG/WTLS curve over a 112 bit prime field"
        WAP_WSG_IDM_ECID_WTLS7 = "wap-wsg-idm-ecid-wtls7: SECG/WTLS curve over a 160 bit prime field"
        WAP_WSG_IDM_ECID_WTLS8 = "wap-wsg-idm-ecid-wtls8: WTLS curve over a 112 bit prime field"
        WAP_WSG_IDM_ECID_WTLS9 = "wap-wsg-idm-ecid-wtls9: WTLS curve over a 160 bit prime field"
        WAP_WSG_IDM_ECID_WTLS10 = "wap-wsg-idm-ecid-wtls10: NIST/SECG/WTLS curve over a 233 bit binary field"
        WAP_WSG_IDM_ECID_WTLS11 = "wap-wsg-idm-ecid-wtls11: NIST/SECG/WTLS curve over a 233 bit binary field"
        WAP_WSG_IDM_ECID_WTLS12 = "wap-wsg-idm-ecid-wtls12: WTLS curve over a 224 bit prime field"
        BRAINPOOLP160R1 = "brainpoolP160r1: RFC 5639 curve over a 160 bit prime field"
        BRAINPOOLP160T1 = "brainpoolP160t1: RFC 5639 curve over a 160 bit prime field"
        BRAINPOOLP192R1 = "brainpoolP192r1: RFC 5639 curve over a 192 bit prime field"
        BRAINPOOLP192T1 = "brainpoolP192t1: RFC 5639 curve over a 192 bit prime field"
        BRAINPOOLP224R1 = "brainpoolP224r1: RFC 5639 curve over a 224 bit prime field"
        BRAINPOOLP224T1 = "brainpoolP224t1: RFC 5639 curve over a 224 bit prime field"
        BRAINPOOLP256R1 = "brainpoolP256r1: RFC 5639 curve over a 256 bit prime field"
        BRAINPOOLP256T1 = "brainpoolP256t1: RFC 5639 curve over a 256 bit prime field"
        BRAINPOOLP320R1 = "brainpoolP320r1: RFC 5639 curve over a 320 bit prime field"
        BRAINPOOLP320T1 = "brainpoolP320t1: RFC 5639 curve over a 320 bit prime field"
        BRAINPOOLP384R1 = "brainpoolP384r1: RFC 5639 curve over a 384 bit prime field"
        BRAINPOOLP384T1 = "brainpoolP384t1: RFC 5639 curve over a 384 bit prime field"
        BRAINPOOLP512R1 = "brainpoolP512r1: RFC 5639 curve over a 512 bit prime field"
        BRAINPOOLP512T1 = "brainpoolP512t1: RFC 5639 curve over a 512 bit prime field"
        FRP256V1 = "FRP256v1: FRP256v1"
        ID_GOSTR3410_2001_TESTPARAMSET = "id-GostR3410-2001-TestParamSet: GOST R 34.10-2001 Test Curve"
        ID_GOSTR3410_2001_CRYPTOPRO_A_PARAMSET = "id-GostR3410-2001-CryptoPro-A-ParamSet: GOST R 34.10-2001 CryptoPro-A"
        ID_GOSTR3410_2001_CRYPTOPRO_B_PARAMSET = "id-GostR3410-2001-CryptoPro-B-ParamSet: GOST R 34.10-2001 CryptoPro-B"
        ID_GOSTR3410_2001_CRYPTOPRO_C_PARAMSET = "id-GostR3410-2001-CryptoPro-C-ParamSet: GOST R 34.10-2001 CryptoPro-C"
        ID_GOSTR3410_2001_CRYPTOPRO_XCHA_PARAMSET = "id-GostR3410-2001-CryptoPro-XchA-ParamSet: GOST R 34.10-2001 CryptoPro-XchA"
        ID_GOSTR3410_2001_CRYPTOPRO_XCHB_PARAMSET = "id-GostR3410-2001-CryptoPro-XchB-ParamSet: GOST R 34.10-2001 CryptoPro-XchB"
        ID_TC26_GOST_3410_2012_512_PARAMSETA = "id-tc26-gost-3410-2012-512-paramSetA: GOST R 34.10-2012 TC26-A"
        ID_TC26_GOST_3410_2012_512_PARAMSETB = "id-tc26-gost-3410-2012-512-paramSetB: GOST R 34.10-2012 TC26-B"


def load_curve_types():
    from cryptography.hazmat.primitives.asymmetric import ec
    for each_available_curve in EllipticCurve.get_available_elliptic_curves():
        curve_type = each_available_curve.get_oid_type()
        ec._CURVE_TYPES[each_available_curve.name] = curve_type
