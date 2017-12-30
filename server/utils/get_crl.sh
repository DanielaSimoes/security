#!/bin/bash
# Fetches CRLs of the portuguese citizen card

mkdir -p crls
cd crls
rm -v *.crl

CERT="cc_sub-ec_cidadao_autenticacao_crl0010_p0001.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}

CERT="cc_sub-ec_cidadao_autenticacao_crl0010_delta_p0001.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0010_p0002.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0010_delta_p0002.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0010_p0003.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0010_delta_p0003.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0010_p0004.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0010_delta_p0004.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0010_p0005.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0010_delta_p0005.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0010_p0006.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0010_delta_p0006.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0010_p0007.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0010_delta_p0007.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0010_p0008.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0010_delta_p0008.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0011_p0001.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0011_delta_p0001.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0011_p0002.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0011_delta_p0002.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0011_p0003.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0011_delta_p0003.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_ec_cidadao_crl001_crl.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_ec_cidadao_crl002_crl.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_ec_cidadao_crl003_crl.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_assinatura_crl0001.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_assinatura_crl0001_delta.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_assinatura_crl0002.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_assinatura_crl0002_delta.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0001.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0001_delta.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0002.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0002_delta.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0003_p0001.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0003_delta_p0001.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0003_p0002.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0003_delta_p0002.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0003_p0003.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0003_delta_p0003.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0003_p0004.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0003_delta_p0004.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0003_p0005.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0003_delta_p0005.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0003_p0006.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0003_delta_p0006.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0003_p0007.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0003_delta_p0007.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0004_p0001.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0004_delta_p0001.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0004_p0002.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0004_delta_p0002.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0004_p0003.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0004_delta_p0003.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0004_p0004.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0004_delta_p0004.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0004_p0005.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0004_delta_p0005.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0004_p0006.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0004_delta_p0006.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0005_p0001.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0005_delta_p0001.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0005_p0002.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0005_delta_p0002.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0005_p0003.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0005_delta_p0003.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0005_p0004.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0005_delta_p0004.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0005_p0005.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0005_delta_p0005.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0006_p0001.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0006_delta_p0001.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0006_p0002.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0006_delta_p0002.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0006_p0003.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0006_delta_p0003.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0006_p0004.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0006_delta_p0004.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0006_p0005.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0006_delta_p0005.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0006_p0006.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0006_delta_p0006.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0007_p0001.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0007_delta_p0001.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0008_p0001.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0008_delta_p0001.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0008_p0002.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0008_delta_p0002.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0008_p0003.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0008_delta_p0003.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0008_p0004.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0008_delta_p0004.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0008_p0005.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0008_delta_p0005.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0008_p0006.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0008_delta_p0006.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0008_p0007.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0008_delta_p0007.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0009_p0001.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0009_delta_p0001.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0009_p0002.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0009_delta_p0002.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0009_p0003.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0009_delta_p0003.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0009_p0004.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0009_delta_p0004.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0009_p0005.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0009_delta_p0005.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0009_p0006.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0009_delta_p0006.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0009_p0007.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}


CERT="cc_sub-ec_cidadao_autenticacao_crl0009_delta_p0007.crl"
wget "https://pki.cartaodecidadao.pt/publico/lrc/"${CERT}
echo ${CERT}
openssl crl -inform DER -in ${CERT} -outform PEM -out ${CERT}