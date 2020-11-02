#
# test by kyoung chip , jang
#

from tkinter import messagebox
import ctypes

def test( data ) :
    messagebox.showinfo("Basic Example", "a Basic Tk MessageBox : %s" % data)
    return( "receive = %s " % data )

def messageBox(title, text, style):
	return ctypes.windll.user32.MessageBoxW(None, text, title, style)
