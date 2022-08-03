import sys, os
from . import miniCapa

# sys.path.append('C:\\Users\\aaaddress1\\Desktop\\Akali-main\\Akali\\Subsystem\\miniCapa\\')

absPath_miniCapa = os.path.join(os.path.dirname(os.path.abspath(__file__)), "miniCapa")
sys.path.append(absPath_miniCapa)

# sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)),os.pardir))
