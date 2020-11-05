#
# test by kyoung chip , jang
#

from tkinter import messagebox
import ctypes
import hashlib
improt os

def test( data ) :
    messagebox.showinfo("Basic Example", "a Basic Tk MessageBox : %s" % data)
    return( "receive = %s " % data )

def messageBox(title, text, style):
	return ctypes.windll.user32.MessageBoxW(None, text, title, style)


def find_str():
    test = os.system('strings.exe test.bin | findstr /R [0-9]*\.[0-9]*\.[0-9]*\.[0-9]')
    print(test)
    return 0