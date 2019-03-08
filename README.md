# an1310-python
A python command-line implementation of the AN1310 Bootloader for PIC16 microcontrollers.

This is a simple python implementation of the AN1310 bootloader for PIC16 microcontrollers (see relevant application note from Microchip). The bootloader is used to program a PIC MCU through a serial port, most likely an USB-to-serial converter, provided that you have the bootloader firmware already programmed in the PIC itself.

The program can be invoked with just the executable file (in hex format) as argument and it will try to autodetect the serial port (see below). Otherwise you can pass the port name with `-p` parameter. Try `./an1310.py -h` for help.

Currently only the PIC16F887 is supported and tested, but the program can easily be extended to other devices (see below).

The bootloading procedure is as follows:
- assert break on serial port and ask user to reset the PIC
- connect to bootloader firmware (stop here if no hex file given)
- write user program
- verify user program
- run user program
- run a serial terminal to interact with the user program through the same serial port

In the last step a serial terminal is started on the user's side, using python package "serial.tools.miniterm", so that you can exchange data with the user program, if needed, through the same connection, once the control is passed to the user program.

Note: you may have warnings like "`!! ignoring address 0x2007`". This is normal if your code defines configuration bits, EEPROM initialization values, ID words or other features at virtual addresses. Those addresses are outside the actual program memory and cannot be self-written by the PIC firmware, but can only be set by an external programmer. You must set those values when you initially write the bootloader firmware to the PIC flash.

Example of running the program:
```
$ ./an1310.py myprog.X.production.hex

Using port /dev/ttyUSB0
Reset PIC if not in bootloader mode, then press Enter...
Connecting...
Found device PIC16F887, bootloader v.1.5
!! ignoring address 0x2007
!! ignoring address 0x2008
Writing...
Verifying...
Running...
Launching serial terminal...
--- Miniterm on /dev/ttyUSB0  19200,8,N,1 ---
--- Quit: Ctrl+C | Menu: Ctrl+T | Help: Ctrl+T followed by Ctrl+H ---
ready
023 C
022 C

--- exit ---
```

Limitations and how to extend it
================================

Currently only the PIC16F887 is supported. The `device_db` variable lists the supported devices and their parameters, in turn imported from the `devices.db` SQLite database distributed with the original AN1310 source code (see comments in the code for the details). Other devices can easily be added in the same way, but currently we cannot test them.

The program only supports devices with auto-erase of flash blocks during writing. Actually many PIC16 devices fall in that category, and the program will check that when connecting to the MCU, and fail otherwise. If you want to know if your device is of the auto-erase kind, you can check the corresponding include file in the MPLAB installation, for example `p16f887.inc` for PIC16F887: if a "FREE" bit is defined for EECON1 register, the device must explicitly erase flash, and so cannot be used with the program as-is. Otherwise it has no erase operation and it should be ok. For other devices it should be easy to implement an erase routine in addition to write.

The autodetection of the serial port looks for an USB-backed port with VID/PID 0x0403/0x6015. This corresponds with an FTDI FT230X USB-to-serial converter, used in our specific board. You can easily change the VID and PID in the code, or add a different search criterion.

Connection to bootloader firmware is attempted with a baud rate of 115200, while the serial terminal after the user program is run is set at 19200. You can easily change them.

Hints
=====

Be sure to have read and write permissions to the serial port device, and have the needed drivers installed. For all the rest, the same constraints as the original AN1310 program apply, so if it works there you should have no problems. 

The program depends on several python modules, see the imports at the beginning of the code.
