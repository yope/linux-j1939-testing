#!/usr/bin/env python3
#
# vim: set tabstop=4 shiftwidth=4 :
#
# Copyright (c) 2018 Protonic Holland
#
# Written by David Jander (david@protonic.nl)
#
# This file may be used under the terms of the GNU General Public License, version 2.
# For more details see: https://www.gnu.org/licenses/gpl-2.0.html

from .isocan import IsoCanLink
import asyncio

class TestJ1939:
	def __init__(self, ifname, peeraddr):
		self.loop = asyncio.get_event_loop()
		self.preferred_sa = 128
		self.peeraddr = peeraddr
		self.link = IsoCanLink(ifname, self, self.loop, b'\xff\xff\x9f\x34\x00\x1d\x00\x80', self.preferred_sa)
		self.rxqueues = {}

	def _get_rxqueue(self, pgn):
		return self.rxqueues.setdefault(pgn, asyncio.Queue())

	def handle_can_data(self, pf, da, sa, data):
		if pf > 240 or da == 255:
			ps = da # Broadcast or PDU format 2
		else:
			ps = 0 # PDU format 1
		pgn = self.link.pack_pgn(0, pf, ps)
		print("RX: pgn = {:06x} sa = {:02x} data = {}".format(pgn, sa, self.hexdump(data)))
		self._get_rxqueue(pgn).put_nowait((sa, data))

	def hexdump(self, data, maxlen=16):
		n = min(len(data), maxlen)
		return " ".join(["{:02x}".format(data[i]) for i in range(n)]) + ("..." if n < len(data) else "")

	async def wait_for_response(self, pgn, timeout=1):
		try:
			ret = await asyncio.wait_for(self._get_rxqueue(pgn).get(), timeout)
		except asyncio.TimeoutError:
			ret = None
		return ret

	async def test_address_claim(self):
		self.link.start_address_claim()
		self.link.send_request_PGN(255, 0xee00)
		await asyncio.sleep(0.25)

	def send_data(self, pgn, data):
		self.link.send_iso_message_pgn(pgn, self.peeraddr, data)


class TestVT(TestJ1939):
	RXPGN = 0xe600
	TXPGN = 0xe700
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

	async def test_frame(self):
		self.send_data(self.TXPGN, b'\xc0\xff\x03\x04\x05\x06\xff\xff')
		ret = await self.wait_for_response(self.RXPGN)
		assert(ret is not None)
		sa, data = ret
		assert(sa == self.peeraddr)
		assert(data[0] == 0xc0)

	async def test_tp(self, size=100):
		data = bytes([x & 255 for x in range(size)])
		self.send_data(self.TXPGN, data)

	async def run_coro(self):
		await self.test_address_claim()
		await self.test_frame()
		await self.test_tp(10)
		await asyncio.sleep(0.2)
		await self.test_tp(100)
		await asyncio.sleep(0.2)
		await self.test_tp(1000)
		await asyncio.sleep(1.0)
		await self.test_tp(10000)
		await asyncio.sleep(4.0)

	def run(self):
		self.loop.run_until_complete(self.run_coro())
		print("Done.")

if __name__ == "__main__":
	t = TestVT("vcan0", 38)
	t.run()
