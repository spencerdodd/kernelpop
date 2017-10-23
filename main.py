import MySQLdb
from src.kernelpop import kernelpop

exploit_db = MySQLdb.connect(
	host="localhost",
	user="kernelpop",
	passwd="kernelpop",
	db="exploit_db")

kernelpop(exploit_db)