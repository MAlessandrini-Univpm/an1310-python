#!/usr/bin/env python3

# an1310.py
# Copyright (C) 2019  Michele Alessandrini  [https://github.com/malessandrini/an1310-python]

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3
# as published by the Free Software Foundation.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import serial
import serial.tools.list_ports
import serial.tools.miniterm
import sys
import crcmod
import re
import time
import argparse


# example PIC16F887:
#  write: 8W (16B)
#  erase: 16W (32B)
#  erase is automatic when writing first 8 words in a 16-word block


def main(port, hexFile):
	bl = Bootloader(port)
	print('Using port', bl.port.name)
	bl.set_break(True)
	input('Reset PIC if not in bootloader mode, then press Enter...')
	bl.set_break(False)
	print('Connecting...')
	bl.connect()
	print('Found device ' + bl.dev_info[2] + ', bootloader v.' + str(bl.bl_info['version_major']) + '.' + str(bl.bl_info['version_minor']))
	if hexFile is None:
		print('No hex file given, exiting.')
		return 0
	bl.load_hex_file(hexFile)
	print('Writing...')
	bl.write()
	print('Verifying...')
	bl.verify()
	print('Running...')
	bl.run()
	print('Launching serial terminal...')

	# run serial.tools.miniterm (some code copied from miniterm's main function)
	bl.port.baudrate = 19200  # reuse our port without closing and reopening it

	# define our own filter to display non-printable chars as '<nn>' hexadecimal
	class MyFilter(serial.tools.miniterm.Transform):
		def rx(self, text):
			r = ''
			for c in text:
				if ' ' <= c < '\x7f' or c in '\r\n\b\t':
					r += c
				else:
					r += '<' + '{:02x}'.format(ord(c)) + '>'
			return r
		echo = rx
	# add it to miniterm's table
	serial.tools.miniterm.TRANSFORMATIONS['my_filter'] = MyFilter

	miniterm = serial.tools.miniterm.Miniterm(bl.port, filters=('my_filter',), eol='lf')
	miniterm.exit_character = serial.tools.miniterm.unichr(0x03)  # CTRL-C
	miniterm.menu_character = serial.tools.miniterm.unichr(0x14)  # CTRL-T
	miniterm.set_rx_encoding('ascii')
	miniterm.set_tx_encoding('ascii')

	sys.stderr.write('--- Miniterm on {p.name}  {p.baudrate},{p.bytesize},{p.parity},{p.stopbits} ---\n'.format(
		p=miniterm.serial))
	sys.stderr.write('--- Quit: {} | Menu: {} | Help: {} followed by {} ---\n'.format(
		serial.tools.miniterm.key_description(miniterm.exit_character),
		serial.tools.miniterm.key_description(miniterm.menu_character),
		serial.tools.miniterm.key_description(miniterm.menu_character),
		serial.tools.miniterm.key_description('\x08')))

	miniterm.start()
	try:
		miniterm.join(True)
	except KeyboardInterrupt:
		pass
	sys.stderr.write("\n--- exit ---\n")
	miniterm.join()
	miniterm.close()




class Bootloader:
	STX = 0x0F
	ETX = 0x04
	DLE = 0x05
	crc16_func = crcmod.mkCrcFun(0x11021, 0, False, 0)


	def __init__(self, port = None, baudrate = None, verbose = False):
		self.port = None
		self.bl_info = {}
		self.dev_info = None
		self.verbose = verbose

		if baudrate is None: baudrate = 115200
		if port is None:
			all_ports =  serial.tools.list_ports.comports()
			for p in all_ports:
				if p.vid == 0x0403 and p.pid == 0x6015:
					port = p.device
					break
			if port is None:
				raise RuntimeError('device not found, is the driver installed?')
		self.port = serial.Serial(port, baudrate)


	def set_break(self, b):
		self.port.break_condition = b


	def connect(self):
		self.port.reset_input_buffer()  # needed if previous program was writing to serial
		self.send_command(b'\x00')
		reply = self.get_reply(12)
		self.bl_info['version_major'] = reply[2]
		self.bl_info['version_minor'] = reply[3]
		self.bl_info['family_id'] = reply[5] & 0x0F
		self.bl_info['command_mask'] = reply[4] | ((reply[5] & 0xF0) << 4)
		self.bl_info['start_bootloader'] = reply[6] | (reply[7] << 8) | (reply[8] << 16) | (reply[9] << 24)
		self.bl_info['end_bootloader'] = self.bl_info['start_bootloader'] + (reply[0] | (reply[1] << 8))
		self.bl_info['dev_id'] = reply[10] | (reply[11] << 8)
		for d in Bootloader.device_db:
			if d[0] == self.bl_info['dev_id'] and d[1] == self.bl_info['family_id']:
				self.dev_info = d
		if self.dev_info is None:
			raise RuntimeError('unsupported device')
		if self.bl_info['command_mask'] != 0:
			raise RuntimeError('erase not implemented yet (device has no auto-erase)')
		# some sanity checks
		self.bytes_per_word = self.dev_info[3]
		self.words_write = self.dev_info[4]
		self.words_erase = self.dev_info[5]
		self.words_per_packet = 32
		if self.words_per_packet % self.words_erase or self.words_per_packet % self.words_write or self.bytes_per_word != 2 \
			or self.bl_info['start_bootloader'] == 0 or self.bl_info['start_bootloader'] % self.words_erase:
				raise RuntimeError('I don\'t like these numbers!')


	def load_hex_file(self, filename):
		self.hex_data = []  # lists [addr, [data]]
		upper_address = 0
		eof = False
		err = RuntimeError('hex file format error')
		with open(filename, 'r') as f:
			for line in f:
				line = line.rstrip()
				if not len(line): continue
				if not re.fullmatch('^:([0-9a-fA-F][0-9a-fA-F])+$', line):
					raise err
				v = bytes.fromhex(line[1:])
				if eof or len(v) < 5 or len(v) != v[0] + 5 or v[0] % 2:
					raise err
				if ((256 - sum(v[:-1])) & 0xFF) != v[-1]:  # checksum
					raise err
				if v[3] == 1 and v[0] == 0:
					eof = True
				elif v[3] == 4 and v[0] == 2:
					upper_address = v[4] * 256 + v[5]
				elif v[3] == 0:
					addr = (upper_address * 65536 + v[1] * 256 + v[2]) // 2
					words = [v[i] + v[i + 1] * 256 for i in range(4, len(v) - 1, 2)]
					if addr >= self.dev_info[7]:
						print('!! ignoring address', hex(addr))
						continue
					if not len(self.hex_data) or self.hex_data[-1][0] + len(self.hex_data[-1][1]) != addr:
						self.hex_data.append([addr, []])
					self.hex_data[-1][1].extend(words)
				else:
					raise err
			if not eof or not len(self.hex_data): raise err

		if self.verbose:
			print('Program:', [(hex(r[0]), len(r[1])) for r in self.hex_data])
		#for a in self.hex_data: print(hex(a[0]), len(a[1]), [hex(x) for x in a[1]])

		# we need an extra erase-block before bootloader to remap reset vector
		limit = self.bl_info['start_bootloader'] - self.words_erase
		#print('limit', hex(limit))

		# we must ensure that all ranges are multiple of words_erase
		# and aligned at words_erase
		for i in range(0, len(self.hex_data)):
			r = self.hex_data[i]
			r_prev = self.hex_data[i - 1] if i > 0 else None
			r_next = self.hex_data[i + 1] if i < (len(self.hex_data) - 1) else None
			if r_prev is not None and r_prev[0] + len(r_prev[1]) > r[0]:
				raise RuntimeError('overlapping program ranges')
			addr = r[0]
			if r[0] % self.words_erase:
				# not aligned
				addr = r[0] - (r[0] % self.words_erase) # correct starting address
				if r_prev is None or (r_prev[0] + len(r_prev[1])) <= addr:
					r[1] = [0] * (r0 - addr) + r[1]
					r[0] = addr
				elif (r_prev[0] + len(r_prev[1])) == r[0]:
					pass  # ok, they will be merged
				else:
					# right alignment of previous range should have been fixed at previous step
					raise RuntimeError('error reorganizing address ranges')
			if (len(r[1]) + (r[0] - addr)) % self.words_erase:
				newlen = ((len(r[1]) + (r[0] - addr)) // self.words_erase + 1) * self.words_erase - (r[0] - addr)
				if r_next is None or r[0] + newlen <= r_next[0]:
					r[1] += [0] * (newlen - len(r[1]))
				else:
					# we have to merge r with r_next after filling the gap
					r[1] += [0] * (r_next[0] - r[0] - len(r[1]))
					# will be merged later

		# merge ranges that must be merged
		i = 0
		while (i < len(self.hex_data)):
			if i < (len(self.hex_data) - 1) and self.hex_data[i][0] + len(self.hex_data[i][1]) == self.hex_data[i + 1][0]:
				self.hex_data[i][1] += self.hex_data[i + 1][1]
				del self.hex_data[i + 1]
				i = 0  # restart scan
			else:
				i += 1

		if self.hex_data[-1][0] + len(self.hex_data[-1][1]) > limit:
			raise RuntimeError('program not fitting in flash')

		# check that program starts with a GOTO to start address (reset vector)
		r = self.hex_data[0]
		if r[0] != 0 or len([opcode for opcode in r[1][0:4] if opcode & 0x3800 == 0x2800]) == 0:
			raise RuntimeError('program does not appear to contain a valid reset vector')

		# remap reset vector for bootloader
		self.hex_data.append([limit, [0] * self.words_erase])
		self.hex_data[-1][1][-5] = 0x018A  # clrf PCLATH
		self.hex_data[-1][1][-4:] = self.hex_data[0][1][:4]
		operand = self.bl_info['start_bootloader'] + 3
		self.hex_data[0][1][0] = 0x3000 | ((operand >> 8) & 0xFF)  # movlw high(BootloaderBreakCheck)
		self.hex_data[0][1][1] = 0x008A                            # movwf PCLATH
		self.hex_data[0][1][2] = 0x2800 | (operand & 0x7FF)        # goto BootloaderBreakCheck

		#print('--------------------------------------')
		#for a in self.hex_data: print(hex(a[0]), len(a[1]), [hex(x) for x in a[1]])
		if self.verbose:
			print('Adjusted program:', [(hex(r[0]), len(r[1])) for r in self.hex_data])

		for a in self.hex_data:
			for b in a[1]:
				if b > 0x3FFF:
					print('Warning: opcode > 3FFF:', hex(b))


	def write(self):
		for r in self.hex_data:
			addr = r[0]
			while addr < (r[0] + len(r[1])):
				words = min(self.words_per_packet, r[0] + len(r[1]) - addr)
				cmd = [ 0x04, (addr & 0xFF), ((addr >> 8) & 0xFF), ((addr >> 16) & 0xFF), 0, words // self.words_write]
				cmd += sum([[w & 0xFF, (w >> 8) & 0xFF ] for w in r[1][addr - r[0] : addr - r[0] + words]], [])
				#print(hex(addr), words, [hex(x) for x in cmd])
				if self.verbose:
					print('Writing', hex(addr), '(', words, 'words)')
				self.send_command(bytes(cmd))
				if self.get_reply(1) != b'\x04':
					raise RuntimeError('wrong reply')
				addr += words


	def verify(self):
		# verify CRCs
		for r in self.hex_data:
			blocks = len(r[1]) // self.words_erase
			if self.verbose:
				print('Verifying', hex(r[0]), blocks, 'blocks')
			cmd = [ 0x02, (r[0] & 0xFF), ((r[0] >> 8) & 0xFF), ((r[0] >> 16) & 0xFF), 0, (blocks & 0xFF), (blocks >> 8) & 0xFF]
			self.send_command(bytes(cmd))
			reply = self.get_reply(blocks * 2, False)
			#print([hex(b) for b in reply])
			crc = 0  # not reset to 0 for every block!
			for i in range(0, len(r[1]), self.words_erase):
				crc = Bootloader.crc16_func(bytes(sum([[w & 0xFF, (w >> 8) & 0xFF] for w in r[1][i : i + self.words_erase]], [])), crc)  # previous CRC passed
				#print('@@@', hex(crc))
				if crc != reply[2 * i // self.words_erase] + reply[2 * i // self.words_erase + 1] * 256:
					raise RuntimeError('verify error')


	def run(self):
		self.send_command(b'\x08')
		self.port.flush()  # be sure command is sent before reusing serial port


	def send_command(self, data):
		crc16 = Bootloader.crc16_func(data)
		self.port.timeout = 0.1
		retry = 30
		while retry:
			retry -= 1
			self.port.write([Bootloader.STX])
			#print('.', end='')
			r = self.port.read(1)
			if not len(r): continue
			if r[0] != Bootloader.STX:
				raise RuntimeError('wrong reply')
			break
		if not retry:
			raise RuntimeError('no reply')
		pkt = self.escape(data + bytes([ crc16 % 256, crc16 // 256 ]))
		self.port.write(pkt + bytes([ Bootloader.ETX ]))


	def get_reply(self, payload_len, crc = True):
		self.port.timeout = 1
		pkt_len = payload_len + 3 if crc else payload_len + 1
		pkt = self.port.read(pkt_len)
		# there can be more bytes in case of escaped bytes
		time.sleep(0.01)
		if self.port.in_waiting:
			pkt += self.port.read(self.port.in_waiting)
		pkt = self.unescape(pkt)
		if len(pkt) != pkt_len or pkt[-1] != Bootloader.ETX:
			raise RuntimeError('no reply or wrong packet received')
		if crc:
			if Bootloader.crc16_func(pkt[:-3]) != (pkt[-3] + pkt[-2] * 256):
				raise RuntimeError('CRC error')
			return pkt[:-3]
		else:
			return pkt[:-1]


	def escape(self, data):
		r = bytearray()
		for b in data:
			if b == Bootloader.STX or b == Bootloader.ETX or b == Bootloader.DLE:
				r.extend([ Bootloader.DLE, b ])
			else:
				r.append(b)
		return r


	def unescape(self, data):
		r = bytearray()
		escape = False
		for b in data:
			if b == Bootloader.DLE and not escape:
				escape = True
			else:
				r.append(b)
				escape = False
		return r


	device_db = (
		# read from original devices.db (sqlite), table DEVICES, excluding DEVICEROWID field
		# 0: device_id, 1: family_id, 2: PARTNAME, 3: BYTESPERWORDFLASH, 4: WRITEFLASHBLOCKSIZE, 5: ERASEFLASHBLOCKSIZE, 6: STARTFLASH, 7: ENDFLASH,
		# 8: STARTEE, 9: ENDEE, 10: STARTUSER, 11: ENDUSER, 12: STARTCONFIG, 13: ENDCONFIG, 14: STARTDEVICEID, 15: ENDDEVICEID, 16: DEVICEIDMASK, 17: STARTGPR, 18: ENDGPR
		(260,2,'PIC16F887',2,8,16,0,8192,8448,8704,8192,8196,8199,8201,8198,8199,16352,0,512),
	)


###########################

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument('hexFile', help='executable program in hex format, optional', nargs='?')
	parser.add_argument('-p', metavar='port', nargs=1, help='serial port')
	args = parser.parse_args()
	sys.exit(main(None if args.p is None else args.p[0], args.hexFile))
