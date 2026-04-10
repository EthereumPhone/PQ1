/*
 * Copyright 2023-2024 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "gpio_ena_controller.h"
#include "fsl_debug_console.h"

gpio_pin_config_t gpio_config  = {
		kGPIO_DigitalOutput,
		1
};

gpio_pin_config_t gpio_config_zero = {
		kGPIO_DigitalOutput,
		0
};


struct pin_config current_pin = {
		.pin_number = 0,
		.port = NULL,
		.gpio_port = NULL
};

uint8_t pins_port_A[3] = { 1, 2, 255 };
uint8_t pins_port_B[10] = { 2, 3, 9, 10, 11, 18, 19, 20, 23, 255 };
uint8_t pins_port_C[15] = { 0, 1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 16, 17, 255 };
uint8_t pins_port_D[5] = { 0, 1, 2, 3, 255 };
uint8_t pins_port_E[5] = { 24, 25, 26, 255 };

void set_all_pins_to_zero() {
	size_t i = 0;
	while(pins_port_A[i] != 255) {
		PORT_SetPinMux(PORTA, pins_port_A[i], kPORT_MuxAsGpio);
		GPIO_PinInit(GPIOA, pins_port_A[i], &gpio_config_zero);
		i += 1;
	}

	i = 0;
	while(pins_port_B[i] != 255) {
		PORT_SetPinMux(PORTB, pins_port_B[i], kPORT_MuxAsGpio);
		GPIO_PinInit(GPIOB, pins_port_B[i], &gpio_config_zero);
		i += 1;
	}

	i = 0;
	while(pins_port_C[i] != 255) {
		PORT_SetPinMux(PORTC, pins_port_C[i], kPORT_MuxAsGpio);
		GPIO_PinInit(GPIOC, pins_port_C[i], &gpio_config_zero);
		i += 1;
	}

	i = 0;
	while(pins_port_D[i] != 255) {
		PORT_SetPinMux(PORTD, pins_port_D[i], kPORT_MuxAsGpio);
		GPIO_PinInit(GPIOD, pins_port_D[i], &gpio_config_zero);
		i += 1;
	}

	i = 0;
	while(pins_port_E[i] != 255) {
		PORT_SetPinMux(PORTE, pins_port_E[i], kPORT_MuxAsGpio);
		GPIO_PinInit(GPIOE, pins_port_E[i], &gpio_config_zero);
		i += 1;
	}
}

enum return_state is_pin_in_port(uint8_t pin, uint8_t* pins_of_port) {
	size_t i = 0;
	while(pins_of_port[i] != 255) {
		if(pin == pins_of_port[i])
			return SUCCESS;

		i++;
	}

	return ERROR_INVALID_PIN_NUMBER;
}

enum return_state set_current_pin_config(uint8_t pin_number, char port) {
	uint8_t* pins_of_port;
	if(port == 'A' || port == 'a') {
		current_pin.port = PORTA;
		current_pin.gpio_port = GPIOA;
		pins_of_port = pins_port_A;
	}
	else if(port == 'B' || port == 'b') {
		current_pin.port = PORTB;
		current_pin.gpio_port = GPIOB;
		pins_of_port = pins_port_B;
	}
	else if(port == 'C' || port == 'c') {
		current_pin.port = PORTC;
		current_pin.gpio_port = GPIOC;
		pins_of_port = pins_port_C;
	}
	else if(port == 'D' || port == 'd') {
		current_pin.port = PORTD;
		current_pin.gpio_port = GPIOD;
		pins_of_port = pins_port_D;
	}
	else if(port == 'E' || port == 'e') {
			current_pin.port = PORTE;
			current_pin.gpio_port = GPIOE;
			pins_of_port = pins_port_E;
	}
	else {
		PRINTF("ERROR: Invalid I/O port. Got %c expected A,B,C,D,E or a,b,c,d,e\n\r", port);
		return ERROR_INVALID_PORT;
	}

	if(is_pin_in_port(pin_number, pins_of_port) == ERROR_INVALID_PIN_NUMBER) {
		PRINTF("ERROR: Invalid I/O pin. Got %d\n\r", pin_number);
		return ERROR_INVALID_PIN_NUMBER;
	}

	current_pin.pin_number = pin_number;
	return SUCCESS;
}

void enable_clock_for_gpio_ports() {
	CLOCK_EnableClock(kCLOCK_PortA);
	CLOCK_EnableClock(kCLOCK_PortB);
	CLOCK_EnableClock(kCLOCK_PortC);
	CLOCK_EnableClock(kCLOCK_PortD);
	CLOCK_EnableClock(kCLOCK_PortE);
}

enum return_state enable_pin(uint8_t pin_to_enable, char port_to_enable) {
	enum return_state err_ret = SUCCESS;

	PRINTF("INFO: enable_pin received: %d, %c\n\r", pin_to_enable, port_to_enable);
	if (current_pin.gpio_port != NULL && current_pin.port != NULL && current_pin.pin_number != 0) {
		PRINTF("INFO: Clear pin %d\n\r", current_pin.pin_number);
		GPIO_PortClear(current_pin.gpio_port, 1u << current_pin.pin_number);
	}


	err_ret = set_current_pin_config(pin_to_enable, port_to_enable);

	if(err_ret == SUCCESS) {
		PORT_SetPinMux(current_pin.port, current_pin.pin_number, kPORT_MuxAsGpio);
		GPIO_PinInit(current_pin.gpio_port, current_pin.pin_number, &gpio_config);
		PRINTF("INFO: Set %d\n\r", current_pin.pin_number);
	}

	return err_ret;
}
