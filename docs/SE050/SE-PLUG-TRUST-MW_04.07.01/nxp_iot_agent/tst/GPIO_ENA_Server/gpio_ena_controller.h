/*
 * Copyright 2023-2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */
 
#ifndef _GPIO_ENA_CONTROLLER_H_
#define _GPIO_ENA_CONTROLLER_H_

#include "fsl_clock.h"
#include "fsl_port.h"
#include "fsl_gpio.h"

enum return_state {
	SUCCESS = 0,
	ERROR_INVALID_PIN_NUMBER = 1,
	ERROR_INVALID_PORT = 2,
	ERROR_TCP_CONNECTION = 3
};


struct pin_config {
	uint32_t pin_number;
	PORT_Type* port;
	GPIO_Type* gpio_port;
};

enum return_state is_pin_in_port(uint8_t pin, uint8_t* pins_of_port);
enum return_state set_current_pin_config(uint8_t pin, char port);
void enable_clock_for_gpio_ports();
void set_all_pins_to_zero();
enum return_state enable_pin(uint8_t pin_to_enable, char port_to_enable);

#endif /* _GPIO_ENA_CONTROLLER_H_ */
