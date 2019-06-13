import pymongo
from lib.verify import verify

timeout = 2

vuln = ['27017', 'Mongodb']


def check(ip, ports, apps):
    if verify(vuln, ports, apps):
        try:
            conn = pymongo.MongoClient(host=ip, port=27017, serverSelectionTimeoutMS=timeout)
            database_list = conn.list_database_names()
            if not database_list:
                conn.close()
                return
            conn.close()
            return '27017 MongoDB Unauthorized Access'
        except Exception as e:
            pass
            # return '27017 MongoDB fail'
