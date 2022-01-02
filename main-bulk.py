#!/usr/bin/env python

import webbrowser
import tkinter as tk
from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from tkinter.messagebox import showinfo
import ipaddress
import re
import csv

def isValidDomain(str):
    # Regex to check valid
    # domain name.
    regex = "^((?!-)[A-Za-z0-9-]" + "{1,63}(?<!-)\\.)" + "+[A-Za-z]{2,6}"
    # Compile the ReGex
    p = re.compile(regex)

    # If the string is empty
    # return false
    if (str == None):
        return False
    # Return if the string matched the ReGex
    if (re.search(p, str)):
        return True
    else:
        return False


def isValidIP(s):
        # initialize counter
        counter = 0
        # check if period is present
        for i in range(0, len(s)):
            if (s[i] == '.'):
                counter = counter + 1
        if (counter != 3):
            return False
        # check the range of numbers between periods
        st = set()
        for i in range(0, 256):
            st.add(str(i))
        counter = 0
        temp = ""
        for i in range(0, len(s)):
            if (s[i] != '.'):
                temp = temp + s[i]
            else:
                if (temp in st):
                    counter = counter + 1
                temp = ""
        if (temp in st):
            counter = counter + 1

        # verifying all conditions
        if (counter == 4):
            return True
        else:
            return False

def donothing():
   x = 0

def openIPSubnet():
    webbrowser.open("https://www.calculator.net/ip-subnet-calculator.html")

def openMISP():
    webbrowser.open("https://sig01.threatreveal.com/")

def openUserAgent():
    webbrowser.open("http://useragentstring.com/")

def openPortal():
    webbrowser.open("https://ti.baesystems.com/")

def openMalpedia():
    webbrowser.open("https://malpedia.caad.fkie.fraunhofer.de/")

def openURLscan():
    webbrowser.open("https://urlscan.io/")

def openCyberchef():
    webbrowser.open("https://gchq.github.io/CyberChef/")

window = tk.Tk()
window.geometry('700x750+600+100')
window.title("SHALASHEL")
window.resizable(0,0)
window.wm_attributes('-transparentcolor', 'grey')
window.configure(bg='#E3F0F4')
window.iconbitmap('assets/icon.ico')

menubar = Menu(window)
filemenu = Menu(menubar, tearoff=0)
filemenu.add_command(label="IP Subnet Calculator", command=openIPSubnet)
filemenu.add_command(label="MISP", command=openMISP)
filemenu.add_command(label="Portal", command=openPortal)
filemenu.add_command(label="User Agent String", command=openUserAgent)
filemenu.add_command(label="malpedia", command=openMalpedia)
filemenu.add_command(label="urlscan.io", command=openURLscan)
filemenu.add_command(label="CyberChef", command=openCyberchef)
filemenu.add_separator()
filemenu.add_command(label="Exit", command=window.quit)
menubar.add_cascade(label="Resources", menu=filemenu)
window.config(menu=menubar)

frame1 = tk.Frame(master=window, height=100 , bg='#E3F0F4')
frame1.pack(fill=tk.X, pady=20, expand=True)

searchframe = tk.LabelFrame(frame1, text="Type of Search",font = ("Courier",14,"bold"), bg='#BED6DC')

frame3 = tk.Frame(master=window, width=200, height=100 , bg='#E3F0F4')
frame3.pack(fill=tk.X, pady=20, expand=True,)

frame2 = tk.Frame(master=window, height=50, bg='#E3F0F4')
frame2.pack(fill=tk.X, expand=True)

searchframe.pack(fill="both", expand="no")
osintframe = tk.LabelFrame(frame3, text="Open Source Intelligence Websites", font = ("Courier",14,"bold"), bg='#BED6DC')

def sel(): #function for changing organizing gui when selecting different radioButton
    selection = "Enter " + str(selected.get()) + ":"
    label.config(text = selection)
    if str(selected.get()) == 'IP Address' :
        enable_all()
        select_all()
        button_explore.config(state=DISABLED)
        B.config(state=NORMAL)
        entry.config(state=NORMAL)
        resetButton.config(state=NORMAL)
        select_button.config(state=NORMAL)
        deselect_button.config(state=NORMAL)
        chkbtn11.config(state=DISABLED)
        chkbtn11.deselect()
    elif str(selected.get()) == 'Domain':
        enable_all()
        select_all()
        button_explore.config(state=DISABLED)
        B.config(state=NORMAL)
        entry.config(state=NORMAL)
        resetButton.config(state=NORMAL)
        select_button.config(state=NORMAL)
        deselect_button.config(state=NORMAL)
        chkbtn11.config(state=NORMAL)
        chkbtn11.select()
    elif str(selected.get()) == 'APT' or str(selected.get()) == 'Port':
        disable_all()
        deselect_all()
        button_explore.config(state=DISABLED)
        B.config(state=NORMAL)
        entry.config(state=NORMAL)
        resetButton.config(state=NORMAL)
        select_button.config(state=DISABLED)
        deselect_button.config(state=DISABLED)
    elif str(selected.get()) == 'Bulk Search':
        deselect_all()
        enable_all()
        B.config(state=DISABLED)
        button_explore.config(state=NORMAL)
        entry.config(state=DISABLED)
        resetButton.config(state=DISABLED)
        select_button.config(state=NORMAL)
        deselect_button.config(state=NORMAL)
        label.config(text="1.Choose websites from above. \n 2.Press 'Bulk IP or Domain Search' Button.")

entry = tk.Entry(frame2, fg="black", bg="white", width=70)
label = tk.Label(frame2, text='Enter IP Address:', bg='#E3F0F4')
label.config(font=("Courier", 18, 'bold'))
label_file_explorer = tk.Label(frame2, text='', bg='#E3F0F4')
selected = tk.StringVar(searchframe, "IP Address")
choices = (('IP Address', 'IP Address'),
          ('Domain', 'Domain'),
          ('Port','Port'),
           ('APT','APT'),
           ('Bulk Search','Bulk Search'))
#checklist creation
websites1 = tk.IntVar()
websites2 = tk.IntVar()
websites3 = tk.IntVar()
websites4 = tk.IntVar()
websites5 = tk.IntVar()
websites6 = tk.IntVar()
websites7 = tk.IntVar()
websites8 = tk.IntVar()
websites9 = tk.IntVar()
websites10 = tk.IntVar()
websites11 = tk.IntVar()
chkbtn1 = tk.Checkbutton(osintframe, text="VirusTotal", variable=websites1, font = ("arial",11), onvalue=1, bg = '#BED6DC')
chkbtn1.select()
chkbtn2 = tk.Checkbutton(osintframe, text="AbuseIDB", variable=websites2, font = ("arial",11), onvalue=1, bg = '#BED6DC')
chkbtn2.select()
chkbtn3 = tk.Checkbutton(osintframe, text="Grey Noise", variable=websites3, font = ("arial",11), onvalue=1, bg = '#BED6DC')
chkbtn3.select()
chkbtn4 = tk.Checkbutton(osintframe, text="ThreatCrowd", variable=websites4, font = ("arial",11), onvalue=1, bg = '#BED6DC')
chkbtn4.select()
chkbtn5 = tk.Checkbutton(osintframe, text="IP-Tracker", variable=websites5, font = ("arial",11), onvalue=1, bg = '#BED6DC')
chkbtn5.select()
chkbtn6 = tk.Checkbutton(osintframe, text="Censys.io", variable=websites6, font = ("arial",11), onvalue=1, bg = '#BED6DC')
chkbtn6.select()
chkbtn7 = tk.Checkbutton(osintframe, text="Shodan.io", variable=websites7, font = ("arial",11), onvalue=1, bg = '#BED6DC')
chkbtn7.select()
chkbtn8 = tk.Checkbutton(osintframe, text="Talos", variable=websites8, font = ("arial",11), onvalue=1, bg = '#BED6DC')
chkbtn8.select()
chkbtn9 = tk.Checkbutton(osintframe, text="IBM X-Force", variable=websites9, font = ("arial",11), onvalue=1, bg = '#BED6DC')
chkbtn9.select()
chkbtn10 = tk.Checkbutton(osintframe, text="AlienVault", variable=websites10, font = ("arial",11), onvalue=1, bg = '#BED6DC')
chkbtn10.select()
chkbtn11 = tk.Checkbutton(osintframe, text="crt.sh", variable=websites11, state=DISABLED, font = ("arial",11), onvalue=1, bg = '#BED6DC')
chkbtn11.deselect()

color = '#BED6DC'
s1 = ttk.Style()                     # Creating style element
s1.configure('Wild.TRadiobutton',    # First argument is the name of style. Needs to end with: .TRadiobutton
            background=color,
            font = ("arial", 16))         # Setting background to our specified color above

for choice in choices:#create RadioButtons
    r = ttk.Radiobutton(
        searchframe,
        text = choice[0],
        value = choice[1],
        variable = selected,
        command = sel,
        style = 'Wild.TRadiobutton'
    )
    r.pack(fill='x', side=tk.LEFT, padx=10, pady=20)

def check_oisnt():#checklist validation
    vt_ck = websites1.get()
    aidb_ck = websites2.get()
    gn_ck = websites3.get()
    tc_ck = websites4.get()
    it_ck = websites5.get()
    c_ck = websites6.get()
    s_ck = websites7.get()
    t_ck = websites8.get()
    i_ck = websites9.get()
    o_ck = websites10.get()
    crt_ck = websites11.get()
    if vt_ck==1 or aidb_ck==1 or gn_ck==1 or tc_ck==1 or it_ck==1 or c_ck==1 or s_ck==1 or t_ck==1 or i_ck==1 or o_ck ==1 or crt_ck==1:
        return True
    else:
        return False

def osint_ip():
    search = selected.get() #read input from textBox
    virustotal_check = websites1.get()
    abuseidb_check = websites2.get()
    greynoise_check = websites3.get()
    threatcrowd_check = websites4.get()
    iptracker_check = websites5.get()
    censys_check = websites6.get()
    shodan_check = websites7.get()
    talos_check = websites8.get()
    ibm_check = websites9.get()
    otx_check = websites10.get()
    crt_check = websites11.get()

    if entry.get() == '':#empty text box check
        showinfo(
        title='Error',
        message="Search field cannot be empty."
            )
    elif search == "IP Address":#IP search
        try:
            IP = ipaddress.ip_address(entry.get())
            ip_input = entry.get()
            if virustotal_check == 1:
                webbrowser.open("https://www.virustotal.com/gui/ip-address/" + ip_input)
            if abuseidb_check == 1:
                webbrowser.open("https://www.abuseipdb.com/check/" + ip_input)
            if greynoise_check == 1:
                webbrowser.open("https://www.greynoise.io/viz/ip/" + ip_input)
            if threatcrowd_check == 1:
                webbrowser.open("https://www.threatcrowd.org/ip.php?ip=" + ip_input)
            if iptracker_check == 1:
                webbrowser.open("https://www.ip-tracker.org/lookup.php?ip=" + ip_input)
            if censys_check == 1:
                webbrowser.open("https://search.censys.io/hosts/" + ip_input)
            if shodan_check == 1:
                webbrowser.open("https://www.shodan.io/search?query=" + ip_input)
            if talos_check == 1:
                webbrowser.open("https://talosintelligence.com/reputation_center/lookup?search=" + ip_input)
            if ibm_check == 1:
                webbrowser.open("https://exchange.xforce.ibmcloud.com/ip/" + ip_input)
            if otx_check == 1:
                webbrowser.open("https://otx.alienvault.com/indicator/ip/" + ip_input)
        except ValueError:#error message if ip entered is not valid
            showinfo(title='Error',message="Enter a Valid IP Address and try again.")
    elif search == 'Domain':
        domain = entry.get()
        if isValidDomain(domain):#Domain search
            if virustotal_check == 1:
                webbrowser.open("https://www.virustotal.com/gui/domain/" + domain)
            if abuseidb_check == 1:
                webbrowser.open("https://www.abuseipdb.com/check/" + domain)
            if greynoise_check == 1:
                webbrowser.open("https://www.greynoise.io/viz/query/?gnql=" + domain)
            if threatcrowd_check ==1:
                webbrowser.open("https://www.threatcrowd.org/domain.php?domain=" + domain)
            if iptracker_check == 1:
                webbrowser.open("https://www.ip-tracker.org/lookup.php?ip=" + domain)
            if censys_check == 1:
                webbrowser.open("https://search.censys.io/search?resource=hosts&q=" + domain)
            if shodan_check == 1:
                webbrowser.open("https://www.shodan.io/search?query=" + domain)
            if talos_check == 1:
                webbrowser.open("https://talosintelligence.com/reputation_center/lookup?search=" + domain)
            if ibm_check == 1:
                webbrowser.open("https://exchange.xforce.ibmcloud.com/url/" + domain)
            if otx_check == 1:
                webbrowser.open("https://otx.alienvault.com/indicator/domain/" + domain)
            if crt_check == 1:
                webbrowser.open("https://crt.sh/?q=" + domain)
        else:#error message if wrong domain input
            showinfo(title='Error', message="Enter a Valid Domain Name and try again.")
    elif search == "Port":#Port search
        port = entry.get()
        try:
            if port.isnumeric() == True: #check if input is not string
                port = int(entry.get())
                if 1 <= port <= 65535: #port input validation
                    webbrowser.open("https://www.speedguide.net/port.php?port=" + str(port))
                else:
                    raise ValueError
            else:
                raise ValueError
        except ValueError: #Error message if port number is not valid
            showinfo(title='Error', message="Enter a Valid Port Number and try again.")
    elif search == "APT":
        APT = entry.get() #Read from text box
        webbrowser.open("https://apt.thaicert.or.th/cgi-bin/listgroups.cgi?c=&v=&s=&m=&x=" + APT)
    return None

def browseFiles():
    virustotal_check = websites1.get()
    abuseidb_check = websites2.get()
    greynoise_check = websites3.get()
    threatcrowd_check = websites4.get()
    iptracker_check = websites5.get()
    censys_check = websites6.get()
    shodan_check = websites7.get()
    talos_check = websites8.get()
    ibm_check = websites9.get()
    otx_check = websites10.get()
    crt_check = websites11.get()

    filename = ''
    check99 = check_oisnt()  # check if no website is selected
    #file browse for bulk search
    if check99 == True:
        filename = filedialog.askopenfilename(initialdir="/",
                                            title="Select a File",
                                            filetypes=(("csv files",
                                                      "*.csv*"),
                                                     ("all files",
                                                      "*.*")))
    elif check99 == False:
        showinfo(title='Error', message="You need to choose at least one website from above.")

    if filename != '' and check99 == True:
        # Change label contents
        label_file_explorer.configure(text="File Opened: " + filename)
        file = open(filename)
        csvreader = csv.reader(file)
        for row in csvreader:
            if len(row) == 0:
                continue
            read = row[0]
            if isValidDomain(read):
                if virustotal_check == 1:
                    webbrowser.open("https://www.virustotal.com/gui/domain/" + read, new=1)
                if abuseidb_check == 1:
                    webbrowser.open("https://www.abuseipdb.com/check/" + read, new=1)
                if greynoise_check == 1:
                    webbrowser.open("https://www.greynoise.io/viz/query/?gnql=" + read, new=1)
                if threatcrowd_check == 1:
                    webbrowser.open("https://www.threatcrowd.org/domain.php?domain=" + read, new=1)
                if iptracker_check == 1:
                    webbrowser.open("https://www.ip-tracker.org/lookup.php?ip=" + read, new=1)
                if censys_check == 1:
                    webbrowser.open("https://search.censys.io/search?resource=hosts&q=" + read, new=1)
                if shodan_check == 1:
                    webbrowser.open("https://www.shodan.io/search?query=" + read, new=1)
                if talos_check == 1:
                    webbrowser.open("https://talosintelligence.com/reputation_center/lookup?search=" + read, new=1)
                if ibm_check == 1:
                    webbrowser.open("https://exchange.xforce.ibmcloud.com/url/" + read, new=1)
                if otx_check == 1:
                    webbrowser.open("https://otx.alienvault.com/indicator/domain/" + read, new=1)
                if crt_check == 1:
                    webbrowser.open("https://crt.sh/?q=" + read)
            if isValidIP(read):
                if virustotal_check == 1:
                    webbrowser.open("https://www.virustotal.com/gui/ip-address/" + read, new=1)
                if abuseidb_check == 1:
                    webbrowser.open("https://www.abuseipdb.com/check/" + read, new=1)
                if greynoise_check == 1:
                    webbrowser.open("https://www.greynoise.io/viz/ip/" + read, new=1)
                if threatcrowd_check == 1:
                    webbrowser.open("https://www.threatcrowd.org/ip.php?ip=" + read, new=1)
                if iptracker_check == 1:
                    webbrowser.open("https://www.ip-tracker.org/lookup.php?ip=" + read, new=1)
                if censys_check == 1:
                    webbrowser.open("https://search.censys.io/hosts/" + read, new=1)
                if shodan_check == 1:
                    webbrowser.open("https://www.shodan.io/search?query=" + read, new=1)
                if talos_check == 1:
                    webbrowser.open("https://talosintelligence.com/reputation_center/lookup?search=" + read, new=1)
                if ibm_check == 1:
                    webbrowser.open("https://exchange.xforce.ibmcloud.com/ip/" + read, new=1)
                if otx_check == 1:
                    webbrowser.open("https://otx.alienvault.com/indicator/ip/" + read, new=1)
        file.close()
    else:
        label_file_explorer.configure(text="No file opened.")

button_explore = Button(frame2,
                        text = "Bulk IP or Domain Search",
                        command = browseFiles, width=30, font=('Courier', 12, 'bold'), state=DISABLED)

def deselect_all():
    chkbtn1.deselect()
    chkbtn2.deselect()
    chkbtn3.deselect()
    chkbtn4.deselect()
    chkbtn5.deselect()
    chkbtn6.deselect()
    chkbtn7.deselect()
    chkbtn8.deselect()
    chkbtn9.deselect()
    chkbtn10.deselect()
    chkbtn11.deselect()

def select_all():
    chkbtn1.select()
    chkbtn2.select()
    chkbtn3.select()
    chkbtn4.select()
    chkbtn5.select()
    chkbtn6.select()
    chkbtn7.select()
    chkbtn8.select()
    chkbtn9.select()
    chkbtn10.select()
    chkbtn11.select()

def disable_all():
    chkbtn1.config(state=DISABLED)
    chkbtn2.config(state=DISABLED)
    chkbtn3.config(state=DISABLED)
    chkbtn4.config(state=DISABLED)
    chkbtn5.config(state=DISABLED)
    chkbtn6.config(state=DISABLED)
    chkbtn7.config(state=DISABLED)
    chkbtn8.config(state=DISABLED)
    chkbtn9.config(state=DISABLED)
    chkbtn10.config(state=DISABLED)
    chkbtn11.config(state=DISABLED)

def enable_all():
    chkbtn1.config(state=NORMAL)
    chkbtn2.config(state=NORMAL)
    chkbtn3.config(state=NORMAL)
    chkbtn4.config(state=NORMAL)
    chkbtn5.config(state=NORMAL)
    chkbtn6.config(state=NORMAL)
    chkbtn7.config(state=NORMAL)
    chkbtn8.config(state=NORMAL)
    chkbtn9.config(state=NORMAL)
    chkbtn10.config(state=NORMAL)
    chkbtn11.config(state=NORMAL)

def delete_text():
    entry.delete(0, 'end')

def run_func(self):
    osint_ip()
    return None

B = tk.Button(frame2, text ="Search", width=20, font=('Courier', 14, 'bold'), command = osint_ip)
resetButton = tk.Button(frame2, text ="Clear", width=24,font=12, command = delete_text)
select_button = tk.Button(osintframe, text ="Select All", width=20,font=13, command = select_all)
deselect_button = tk.Button(osintframe, text ="Deselect All", width=20,font=13, command = deselect_all)

label_copyright1 = "Copyright Reserved " + "\u00A9" + " 2021 H & M"
label_copyright2 = tk.Label(frame2, text=label_copyright1, bg='#E3F0F4')
label.pack(padx=5, pady=5)
entry.pack(ipady=10, padx=5, pady=5)
entry.bind('<Return>', run_func)

B.pack(padx=5, pady=5)
resetButton.pack(padx=5, pady=5)
label_file_explorer.pack(padx=5, pady=5)
button_explore.pack(padx=5, pady=5)
label_copyright2.pack(padx=5, pady=5)
osintframe.pack(pady= 5, padx= 5)

chkbtn1.grid(row=0, column=0, pady= 5, padx= 5)
chkbtn2.grid(row=0, column=1, pady= 5, padx= 5)
chkbtn3.grid(row=0, column=2, pady= 5, padx= 5)
chkbtn4.grid(row=0, column=3, pady= 5, padx= 5)
chkbtn5.grid(row=1, column=0, pady= 5, padx= 5)
chkbtn6.grid(row=1, column=1, pady= 5, padx= 5)
chkbtn7.grid(row=1, column=2, pady= 5, padx= 5)
chkbtn8.grid(row=1, column=3, pady= 5, padx= 5)
chkbtn9.grid(row=2, column=0, pady= 5, padx= 5)
chkbtn10.grid(row=2, column=1, pady= 5, padx= 5)
chkbtn11.grid(row=2, column=2, pady= 5, padx= 5)
select_button.grid(row=3, column=1, pady= 5, padx= 5)
deselect_button.grid(row=3, column=2, pady= 5, padx= 5)
window.mainloop()