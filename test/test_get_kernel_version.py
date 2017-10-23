import unittest
from src.kernelpop import get_kernel_version


class TestGetKernelVersion(unittest.TestCase):
	def test_dict_length(self):
		test_kernel_version = get_kernel_version()
		self.assertEqual(len(test_kernel_version), 3)
		self.assertGreater(len(test_kernel_version["normal"]), 0)
		self.assertGreater(len(test_kernel_version["aliased"]), 0)
		self.assertGreater(len(test_kernel_version["terse"]), 0)


if __name__ == "__main__":
	unittest.main()