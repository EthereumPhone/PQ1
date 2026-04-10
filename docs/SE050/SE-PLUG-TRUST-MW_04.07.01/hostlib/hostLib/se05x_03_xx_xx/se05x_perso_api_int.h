/* Copyright 2020 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef se05x_perso_API_INT_H
#define se05x_perso_API_INT_H

#include <se05x_perso_api.h>
#include <se05x_perso_cnst.h>

/*
 * @rst
 * +-----------+-------+----------------+
 * | Name      | Value | Description    |
 * +===========+=======+================+
 * | INS_WRITE | 0x01  | Write command. |
 * +-----------+-------+----------------+
 * | INS_READ  | 0x02  | Read command.  |
 * +-----------+-------+----------------+
 * @endrst
 */

#define SE05X_PERSO_INS_WRITE 0x01
#define SE05X_PERSO_INS_READ 0x02

#endif /* se05x_perso_API_INT_H */
