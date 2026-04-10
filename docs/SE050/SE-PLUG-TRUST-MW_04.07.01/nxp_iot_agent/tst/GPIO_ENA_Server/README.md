1. Open MCU Expresso and import sdk example lwip tcp_echo
2. Replace content of `source/lwip_tcpecho_bm.c` with content of `GPIO_ENA_Server.c`
3. Right click the project -> New -> Source Folder -> create `gpio_ena_controller` and `tcp_socket`
4. Into the newly created folder `gpio_ena_controller` add `gpio_ena_controller.h` and `gpio_ena_controller.c`
5. Into the newly created folder `tcp_socket` add `tcp_socket.h` and `tcp_socket.c`
6. Right click the project -> Properties -> C/C++ General -> Paths and Symbols -> Includes -> GNU C -> Add... -> add `/${ProjName}/gpio_ena_controller` and `/${ProjName}/tcp_socket`, tick `Is a workspace path` for both
7. Build