import math
import time
import datetime

start = time.time()
math.factorial(1234567)
end = time.time()


sec = (end - start)
result = datetime.timedelta(seconds=sec)
print(result)

result_list = str(datetime.timedelta(seconds=sec)).split(".")
print(result_list[0])