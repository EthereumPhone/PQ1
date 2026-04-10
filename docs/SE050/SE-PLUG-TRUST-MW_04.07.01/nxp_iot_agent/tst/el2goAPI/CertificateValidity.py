# Copyright 2024 NXP
#
# SPDX-License-Identifier: Apache-2.0
#

from datetime import datetime, timezone
from dateutil.relativedelta import relativedelta


class CertificateValidity:

    __start_date: datetime = None
    __expiration_date: datetime = None

    def __init__(
        self,
        start_date: datetime = datetime.now(timezone.utc),
        expiration_date: datetime = (
            datetime.now(timezone.utc)
            + relativedelta(months=120)
        ),
    ):
        """
        Creates a certificate validity object, with a fixed time interval. (default: now - 10 years)
        Set None as expiration date to disable expiration.

        The validity period will not exceed the validity period of the selected CA.
        """

        self.__start_date = start_date
        self.__expiration_date = expiration_date

    @classmethod
    def fromNumberOfMonths(cls, number_of_months: int):
        """
        Creates a certificate validity object, with given number of months of validity time.
        """
        return cls(
            datetime.now(timezone.utc),
            (datetime.now(timezone.utc) + relativedelta(months=number_of_months)),
        )

    def print(self):
        print("Start:\t" + self.__start_date.strftime("%Y-%m-%dT%H:%M:00.000Z"))

        if(self.__expiration_date != None):
            print("End:\t" + self.__expiration_date.strftime("%Y-%m-%dT%H:%M:00.000Z"))
        else:
            print("End:\tNone")

    def getJsonFormat(self) -> dict:
        result = {
            "validityType": "DATE",
            "validityNotBefore": self.__start_date.strftime("%Y-%m-%dT%H:%M:00.000Z"),
            "validityNotAfter": self.__expiration_date.strftime("%Y-%m-%dT%H:%M:00.000Z")
        }

        return result
