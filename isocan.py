#
# Copyright (c) 2012, 2013 Protonic Holland
#
# vim: set tabstop=4 shiftwidth=4 :
#

import socket
import struct
from collections import deque

CAN_Frame = struct.Struct('=IB3x8s')
TP_CM_RTS_msg = struct.Struct('<xHBBHB')
ETP_CM_RTS_msg = struct.Struct('<xIHB')
ETP_CM_CTS_DPO_msg = struct.Struct('<xBHBHB')
ETP_CM_EOMA_msg = struct.Struct('<BI')

class IsoCanLink(object):
	def __init__(self, ifname, impl, event_handler, isoname, preferred_sa, sendqueuelen=100000):
		self.sock = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
		self.sock.bind((ifname,))
		self.ifname = ifname
		self.NAME = isoname
		self.preferred_sa = preferred_sa
		self.sa = None
		self.impl = impl
		self.event_handler = event_handler
		self.claiming = False
		self._transmitting = False
		self.send_queue = deque(maxlen=sendqueuelen)
		self.reset_link()
		self.pf_handlers = {
			199 : self.handle_etp_td,
			200 : self.handle_etp_cm,
			232 : self.handle_ack,
			234 : self.handle_request_PGN,
			235 : self.handle_tp_td,
			236 : self.handle_tp_cm,
			238 : self.handle_address_claim,
		}
		self.event_handler.add_reader(self.fileno(), self.process_PDU)

	def start_transmitter(self):
		self._transmitting = True
		self.event_handler.add_writer(self.sock.fileno(), self.transmit)

	def stop_transmitter(self):
		self._transmitting = False
		self.event_handler.remove_writer(self.sock.fileno())

	def reset_link(self):
		self.tp_busy = False

	def get_link_status(self):
		if self.claiming:
			return "claiming"
		if self.tp_busy:
			return "tp"
		return "ready"

	def fileno(self):
		return self.sock.fileno()

	def transmitting(self):
		return self._transmitting

	def send_queue_size(self):
		return len(self.send_queue)

	def queue_frame(self, id, data):
		dlc = len(data)
		id |= 0x80000000 # CAN_EFF_FLAG
		frm = CAN_Frame.pack(id, dlc, data)
		self.send_queue.append(frm)
		self.start_transmitter()
		# print(self.sa, ": queue_frame:",hex(id),repr(data[:dlc]))

	def send_frame(self, frm):
		self.sock.send(frm)

	def recv_frame(self):
		frm, addr = self.sock.recvfrom(CAN_Frame.size)
		id, dlc, data = CAN_Frame.unpack(frm)
		# print(self.sa, ": recv_frame:",hex(id),repr(data[:dlc]))
		return id, data[:dlc]

	def pack_id(self, p, dp, pf, ps, sa):
		return (p << 26) | (dp << 24) | (pf << 16) | (ps << 8) | sa

	def unpack_id(self, id):
		return (id >> 26) & 7, (id >> 24) & 1, (id >> 16) & 0xff, (id >> 8) & 0xff, id & 0xff

	def pack_pgn(self, dp, pf, ps):
		return (dp << 16) | (pf << 8) | ps

	def unpack_pgn(self, pgn):
		return (pgn >> 16), (pgn >> 8) & 0xff, pgn & 0xff

	def send_iso_frame(self, p, dp, pf, ps, data):
		self.queue_frame(self.pack_id(p, dp, pf, ps, self.sa), data)

	def _encode_pgn(self, pgn):
		return bytes([pgn & 255, (pgn >> 8) & 255, (pgn >> 16) & 255])

	def send_request_PGN(self, da, pgn):
		self.send_iso_frame(6, 0, 234, da, self._encode_pgn(pgn))

	def send_ack(self, da, ack, pgn):
		if ack:
			data = b'\x00\xff\xff\xff\xff'
		else:
			data = b'\x01\xff\xff\xff\xff'
		data += self._encode_pgn(pgn)
		self.send_iso_frame(6, 0, 232, 255, data)

	def send_address_claimed(self):
		if self.sa is None:
			self.sa = self.preferred_sa
		print("Send address claimed =", self.sa)
		self.send_iso_frame(6, 0, 238, 255, self.NAME)
		self.claiming = True

	def start_address_claim(self):
		self.send_address_claimed()

	def tp_send_cm(self, da, data, pgn):
		# print("tp_send_cm")
		data = bytes(data).ljust(5, b'\xff')
		data += self._encode_pgn(pgn)
		self.send_iso_frame(7, 0, 236, da, data)

	def tp_send_td(self, da, seq, data):
		# print("tp_send_td: seq =", seq)
		assert(len(data) <= 7)
		data = bytes([seq]) + data.ljust(7, b'\xff')
		self.send_iso_frame(7, 0, 235, da, data)

	def etp_send_cm(self, da, data, pgn):
		# print(self.sa, ": etp_send_cm")
		data = bytes(data).ljust(5, b'\xff')
		data += self._encode_pgn(pgn)
		self.send_iso_frame(7, 0, 200, da, data)

	def etp_send_td(self, da, seq, data):
		# print(self.sa, ": etp_send_td: seq =", seq)
		assert(len(data) <= 7)
		data = bytes([seq]) + data.ljust(7, b'\xff')
		self.send_iso_frame(7, 0, 199, da, data)

	def tp_etp_tx_prepare(self, pf, da, data):
		self.tp_data = data
		self.tp_da = da
		self.tp_seq = 1
		n = len(data)
		assert(n >= 9)
		pgn = self.pack_pgn(0, pf, 0)
		if n <= 1785: # TP
			np = (n + 6) // 7
			self.tp_send_cm(da, [16, n & 255, n >> 8, np], pgn)
		else: # ETP
			self.tp_pgn = pgn
			self.etp_send_cm(da, [20, n & 255,
						(n >> 8) & 255,
						(n >> 16) & 255,
						(n >> 24) & 255], pgn)
		self.tp_busy = True

	def tp_tx_next(self):
		while self.tp_count > 0:
			i = (self.tp_seq - 1) * 7
			self.tp_send_td(self.tp_da, self.tp_seq, self.tp_data[i:i+7])
			self.tp_seq += 1
			if self.tp_seq > 255:
				self.tp_seq = 1 # FIXME: Cannot occur in (non-E)TP.
			self.tp_count -= 1

	def etp_tx_next(self):
		# print("ETP: tx count =", self.tp_count, "seq =", self.tp_seq)
		if self.tp_count <= 0: # ETP on hold, do nothing and wait for new CTS
			return
		s = self.tp_seq - 1
		# FIXME: This looks ugly because struct has no support for 24 bit ints...
		l, m, h = (s & 255), (s >> 8) & 255, (s >> 16) & 255
		self.etp_send_cm(self.tp_da, [22, self.tp_count, l, m, h], self.tp_pgn) # Send DPO
		j = 1
		while self.tp_count > 0:
			i = s * 7
			# print(self.sa, ": ETP:  seq =", j, "TD offset", i, "Data:", repr(self.tp_data[i:i+7]))
			self.etp_send_td(self.tp_da, j, self.tp_data[i:i+7])
			s += 1
			if j > 255:
				j = 1 # FIXME: Cannot occur in (non-E)TP.
			self.tp_count -= 1
			j += 1

	def transmit(self):
		if len(self.send_queue) > 0:
			frm = self.send_queue.popleft()
			try:
				self.send_frame(frm)
			except OSError:
				self.send_queue.appendleft(frm)
		else:
			self.stop_transmitter()

	def send_iso_message(self, pf, da, data):
		if len(data) <= 8:
			self.send_iso_frame(6, 0, pf, da, data=data)
		else:
			self.tp_etp_tx_prepare(pf, da, data)

	def send_iso_message_pgn(self, pgn, da, data):
		dp, pf, ps = self.unpack_pgn(pgn)
		if not ps:
			ps = da
		self.send_iso_message(pf, ps, data)

	def process_PDU(self):
		'''Process a PDU according to ISO11783
		   This should be called when there is CAN data available'''
		id, data = self.recv_frame()
		p, dp, pf, ps, sa = self.unpack_id(id)
		if dp == 1:
			return self.process_PDU_pg1(self, pf, ps, sa, data)
		da = ps
		if pf < 240 and da < 255 and da != self.sa:
			return # Not for us.
		pgn = self.pack_pgn(dp, pf, ps)
		handler = self.pf_handlers.get(pf, self.handle_other)
		handler(pf, da, sa, data)

	def etp_send_next_cts(self):
		# print(self.sa, ": etp_send_next_cts from ", self.tp_seq)
		n = (self.tp_mlen + 6) // 7 - self.tp_seq
		self.tp_count = min(255, n)
		s = self.tp_seq + 1
		# FIXME: This looks ugly because struct has no support for 24 bit ints...
		l, m, h = (s & 255), (s >> 8) & 255, (s >> 16) & 255
		self.etp_send_cm(self.tp_sa, [21, self.tp_count, l, m, h], self.tp_pgn) # Send CTS

	def handle_etp_cm(self, pf, da, sa, data):
		# print("HANDLE ETP CM")
		cb = data[0]
		if cb == 20: # RTS
			self.tp_mlen, pgn_l, pgn_h = ETP_CM_RTS_msg.unpack(data)
			self.tp_pgn = pgn_l | (pgn_h << 16)
			self.tp_buf = bytearray(self.tp_mlen)
			self.tp_sa = sa
			self.tp_receiving = True
			self.tp_seq = 0
			self.etp_send_next_cts()
		elif cb == 21: # CTS
			self.tp_count, seq_l, seq_h, pgn_l, pgn_h = ETP_CM_CTS_DPO_msg.unpack(data)
			self.tp_seq = seq_l | (seq_h << 16)
			self.etp_tx_next()
		elif cb == 22: # DPO
			cnt, dpo_l, dpo_h, pgn_l, pgn_h = ETP_CM_CTS_DPO_msg.unpack(data)
			self.etp_dpo = dpo_l | (dpo_h << 16)
			# FIXME: Do nothing now....?
		elif cb == 23: # EOMA
			self.tp_busy = False
		elif cb == 255: # Connection abort
			self.tp_receiving = False
			print('  ETP ABORT: reason:', data[1])
			self.tp_busy = False

	def handle_etp_td(self, pf, da, sa, data):
		sn = data[0]
		ofs = (sn + self.etp_dpo - 1) * 7
		n = min(7, self.tp_mlen - ofs)
		self.tp_buf[ofs:ofs + n] = data[1:n + 1]
		self.tp_count -= 1
		# print(self.sa, ": HANDLE ETP TD tp_count=%d, ofs=%d" % (self.tp_count, ofs))
		# FIXME: Error handling, retransmit, next sequence, etc...
		if self.tp_count <= 0:
			if (self.tp_mlen - ofs) > 7:
				# More packets needed, ask for them...
				self.tp_seq = ofs // 7 + 1
				self.etp_send_next_cts()
			else:
				# End of transfer, send EOMA:
				data = ETP_CM_EOMA_msg.pack(23, self.tp_mlen)
				self.etp_send_cm(self.tp_sa, data, self.tp_pgn)
				dp, pf, ps = self.unpack_pgn(self.tp_pgn)
				self.handle_other(pf, da, sa, bytes(self.tp_buf))
				self.td_receiving = False

	def handle_tp_cm(self, pf, da, sa, data):
		cb = data[0]
		# print(self.sa, ": handle_tp_cm cb =", cb)
		if cb == 16: # RTS
			self.tp_mlen, tp_count, self.tp_maxpkt, pgn_l, pgn_h = TP_CM_RTS_msg.unpack(data)
			self.tp_count = min(self.tp_maxpkt, tp_count)
			self.tp_pgn = pgn_l | (pgn_h << 16)
			self.tp_buf = bytearray(self.tp_mlen)
			self.tp_sa = sa
			self.tp_receiving = True
			print('  mlen=', self.tp_mlen, 'count=', self.tp_count, 'pgn=', hex(self.tp_pgn))
			self.tp_send_cm(self.tp_sa, (17, self.tp_count, 1) ,self.tp_pgn)
		elif cb == 17: # CTS
			self.tp_count = data[1]
			self.tp_seq = data[2]
			self.tp_tx_next()
		elif cb == 19: # EOMsg Ack
			self.tp_busy = False
		elif cb == 255: # Connection abort
			self.tp_receiving = False
			print('  TP ABORT: reason:', data[1])
			self.tp_busy = False

	def handle_tp_td(self, pf, da, sa, data):
		# print("handle_tp_td")
		sn = data[0]
		ofs = (sn - 1) * 7
		n = min(7, self.tp_mlen - ofs)
		self.tp_buf[ofs:ofs + n] = data[1:n + 1]
		self.tp_count -= 1
		# FIXME: Error handling, retransmit, next sequence, etc...
		if self.tp_count <= 0:
			nfrm = (self.tp_mlen + 6) // 7
			self.tp_send_cm(self.tp_sa, (19, self.tp_mlen & 255, self.tp_mlen >> 8, nfrm), self.tp_pgn)
			dp, pf, ps = self.unpack_pgn(self.tp_pgn)
			self.handle_other(pf, da, sa, bytes(self.tp_buf))
			self.td_receiving = False

	def handle_request_PGN(self, pf, da, sa, data):
		dp, pf, ps = data
		print("handle_request_PGN pf =", pf)
		if pf == 238: # Address claim
			self.send_address_claimed()

	def handle_ack(self, pf, da, sa, data):
		print("handle_ack")

	def handle_address_claim(self, pf, da, sa, data):
		print("handle_address_claim sa =", sa)
		if sa == self.sa:
			if data > self.NAME: # FIXME: correct compare?
				self.sa += 1
			self.send_address_claimed() # FIXME!

	def handle_other(self, pf, da, sa, data):
		print("handle_other pf =", pf, "da =", da, "sa =", sa, "data =", repr(data))
		self.impl.handle_can_data(pf, da, sa, data)
