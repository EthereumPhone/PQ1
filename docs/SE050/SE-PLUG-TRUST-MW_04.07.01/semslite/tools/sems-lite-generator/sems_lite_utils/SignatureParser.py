#! python3

# Copyright(C) NXP B.V. 2020
#
#  All rights are reserved. Reproduction in whole or in part is prohibited
#  without the prior written consent of the copy-right owner.
#  This source code and any compilation or derivative thereof is the sole
#  property of NXP B.V. and is provided pursuant to a Software License
#  Agreement. This code is the proprietary information of NXP B.V. and
#  is confidential in nature. Its use and dissemination by any party other
#  than NXP B.V. is strictly limited by the confidential information
#  provisions of the agreement referenced above.

class SignatureParser:
    # Parse the signature according to:
    # Global Platform Secure Element Management Service
    # Card Specification v2.3 – Amendment I - Version 1.0
    # Table 5-1: Authentication Frame
    AUTHENTICATION_FRAME_TLV_TAG = '60'
    AUTHENTICATION_FRAME_INNER_TLV_TAG = '41'
    TLV_LENGTH_PRE = '81'  # Indicating that the length is contained in the next byte

    @staticmethod
    def get_signature(signed_script_filename):
        with open(signed_script_filename, 'r') as signedScript:
            for line in signedScript:
                if line.startswith(SignatureParser.AUTHENTICATION_FRAME_TLV_TAG):
                    auth_frame = line
                    if (auth_frame[2:4] == SignatureParser.TLV_LENGTH_PRE) \
                            and (auth_frame[6:8] == SignatureParser.AUTHENTICATION_FRAME_INNER_TLV_TAG) \
                            and (auth_frame[8:10] == SignatureParser.TLV_LENGTH_PRE):
                        inner_frame_len = int(auth_frame[10:12], 16)
                        signature_len = inner_frame_len - 65 - 16 - 32
                        signature = auth_frame[(-2*(signature_len+1)+1):-1]
                        return signature.upper()
        raise ValueError("The file '" + signed_script_filename
                         + "' does not contain a GP Amd. I Authentication frame with signature.")
