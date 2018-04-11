import os
import json
import unittest
from src.kernelpop import convert_to_digestible, find_exploit_locally, total_exploits, write_digestible_to_file
from src.kernelpop import Kernel, get_kernel_version
from constants import *
from src.kernelpop import initialize_all_exploits

class TestGetKernelVersion(unittest.TestCase):
	def test_digestible_json(self):
		test_uname = "Linux-3.10.0-1-generic-x86_64-with-Ubuntu-14.04-xenial"
		test_kernel = get_kernel_version(uname=test_uname)
		initialized_exploits = initialize_all_exploits("/tmp")
		local_finds = find_exploit_locally(test_kernel, initialized_exploits)
		json_finds = convert_to_digestible(local_finds, digest="json")
		unjson_finds = json.loads(json_finds)
		self.assertEqual(len(unjson_finds[EXPLOIT_AVAILABLE]), len(local_finds[EXPLOIT_AVAILABLE]))

	def test_dump_to_file(self):
		test_uname = "Linux-3.10.0-1-generic-x86_64-with-Ubuntu-14.04-xenial"
		test_kernel = get_kernel_version(uname=test_uname)
		initialized_exploits = initialize_all_exploits("/tmp")
		local_finds = find_exploit_locally(test_kernel, initialized_exploits)
		json_finds = convert_to_digestible(local_finds, digest="json")
		test_outfile = os.path.join(ROOT_DIR, "output.json")
		if os.path.exists(test_outfile):
			os.remove(test_outfile)
		write_digestible_to_file(test_outfile, json_finds)
		self.assertTrue(os.path.exists(test_outfile))
		# remove it so it's not in the project
		if os.path.exists(test_outfile):
			os.remove(test_outfile)


	def test_digestible_xml(self):
		test_uname = "Linux-3.10.0-1-generic-x86_64-with-Ubuntu-14.04-xenial"
		test_kernel = get_kernel_version(uname=test_uname)
		initialized_exploits = initialize_all_exploits("/tmp")
		local_finds = find_exploit_locally(test_kernel, initialized_exploits)
		#xml_finds = convert_to_digestible(local_finds, digest="xml")


if __name__ == "__main__":
	unittest.main()
