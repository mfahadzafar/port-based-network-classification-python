import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import os
import time
import xlrd
from subprocess import PIPE, Popen
import socket
from PyQt5.QtWidgets import QApplication, QPushButton, QTableWidgetItem, QFrame, \
    QHBoxLayout, QWidget, QDialog, QLabel, QLineEdit, QTableWidget, QHeaderView
from PyQt5.QtCore import *
from scapy.all import *
import matplotlib.pyplot as plt
from matplotlib import colors as mcolors
import matplotlib as mpl
mpl.rcParams['font.size'] = 6.0


class GUI(QDialog):
    def __init__(self):
        super().__init__()
        self.resize(500, 380)

        self.tcpdump = None
        self.active = False
        self.file = False

        self.horizontalLayoutWidget = QWidget(self)
        self.horizontalLayoutWidget.setGeometry(QRect(130, 280, 261, 61)) # for start stop
        self.horizontalLayout = QHBoxLayout(self.horizontalLayoutWidget)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)
        self.startButton = QPushButton(self.horizontalLayoutWidget)
        self.stopButton = QPushButton(self.horizontalLayoutWidget)
        self.table = QTableWidget(self)
        self.table.setGeometry(QRect(10, 10, 479, 271))		# for table

        self.table.insertColumn(0)
        self.table.insertColumn(1)
        self.table.insertColumn(2)
        header_labels = ['Application Protocol', 'Percentage Breakdown', '# of Packets']
        self.table.setHorizontalHeaderLabels(header_labels)

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.Stretch)

        self.horizontalLayout.addWidget(self.startButton)
        self.horizontalLayout.addWidget(self.stopButton)
        self.startButton.clicked.connect(self.start)
        self.stopButton.clicked.connect(self.stop)

        self.line_2 = QFrame(self)
        self.line_2.setFrameShape(QFrame.HLine)
        self.line_2.setFrameShadow(QFrame.Sunken)
        self.line_2.setGeometry(QRect(10, 330, 479, 20))
        self.status = QLabel(self)
        self.status.setGeometry(QRect(10, 340, 479, 30))
        self.status.setAlignment(Qt.AlignCenter)

        self.retranslateUi(self)
        QMetaObject.connectSlotsByName(self)

        self.show()

    def retranslateUi(self, Dialog):
        _translate = QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Port-Based Internet Traffic Classifier"))
        self.startButton.setText(_translate("Dialog", "Start"))
        self.stopButton.setText(_translate("Dialog", "Stop"))
        self.status.setText(_translate("Dialog", "Press \'Start\' to begin Packet Capture"))

    def start(self):
        if not self.active:
            self.active = True

            # Clearing table
            for i in reversed(range(self.table.rowCount())):
                self.table.removeRow(i)

            self.tcpdump = Popen(['tcpdump', '-i', 'en0', '-w', 'packetCapture.pcap'], stdout=PIPE)
            self.startButton.setText("In Progress")
            self.status.setText('Press Stop to Classify Packets')

    def stop(self):
        if self.active and not self.file:

            time.sleep(5)

            self.active = False
            if self.tcpdump and self.tcpdump.poll() is None:
                self.tcpdump.terminate()
            self.startButton.setText("Stop")
            self.status.setText('Packets classified')
            percentages, counter, totalPackets = classifyPackets("packetCapture.pcap") 
            self.fill_table(counter=counter, percentages=percentages)
            plot_graph(counter=counter)

            self.startButton.setText("Start")
            self.status.setText("Total Packets Captured : " + str (totalPackets))

    def fill_table(self, counter, percentages):
    	count = 0
    	for key, value in counter.items():
    		self.table.insertRow(count)
    		self.table.setItem(count, 0, QTableWidgetItem(str(key)))
    		self.table.setItem(count, 1, QTableWidgetItem(str(percentages[key]) + '%'))
    		self.table.setItem(count, 2, QTableWidgetItem(str(value)))
    		count += 1


def make_gui():
    app = QApplication(sys.argv)
    ex = GUI()
    sys.exit(app.exec_())

def classifyPackets(input):
	file = rdpcap(input)
	ports = []						# list - to hold all port numbers used in pcap file
	othersCount = 0					# holds count of all ports that can't be classified
	totalPackets = 0				# holds summation of all packets in PCAP File

	for packet in file:

		# IPv4 || IPv6
		if packet.haslayer(IP) or packet.haslayer(IPv6):

			# UDP || TCP || SCTP
			if packet.haslayer(UDP) or packet.haslayer(TCP) or packet.haslayer(SCTP):
				if packet.sport == packet.dport or packet.sport < packet.dport:
					ports.append(packet.sport)
				else:
					ports.append(packet.dport)

			# add it to "others" if not in TCP, UDP, SCTP
			else:
				othersCount += 1

		# add it to "others" if not in IPv4, IPv6
		else:
			othersCount += 1

		totalPackets += 1

	# check for well-defined port number or not (if not -> others)
	for port in ports:
		try:
			socket.getservbyport(port)
		except:
			ports = list(filter((port).__ne__, ports))           # remove all instance of "port"
			othersCount += 1
			continue

	# list of all unique ports
	uniquePorts = set(ports)

	# count all ports
	counter = {} 
	for uniquePort in uniquePorts:
		counter[socket.getservbyport(uniquePort)] = ports.count(uniquePort)
	if othersCount != 0:
		counter['others'] = othersCount			# Add "others" to dictionary


	percentages = {}
	# calculating percentages
	for key, value in counter.items():
		percentages[key] = "{0:.2f}".format((float(value) / float(totalPackets)) * 100)

	return percentages, counter, totalPackets


def plot_graph(counter):

	percentages= []
	apps = []
	colors = dict(mcolors.BASE_COLORS, **mcolors.CSS4_COLORS)
	for key, value in counter.items():
		apps.append(key)
		percentages.append(value)
	
	# The slices will be ordered and plotted counter-clockwise.
	labels = tuple(apps)

	colorList = []
	count = 0
	for key, value in colors.items():
	  colorList.append(key)
	  if count == len(percentages):
	    break;
	  count += 1

	explode = labels

	plt.pie(percentages, labels=labels, colors=colorList,
	        autopct='%1.1f%%', startangle=90)

	# Set aspect ratio to be equal so that pie is drawn as a circle.
	plt.axis('equal')
	plt.show()

make_gui()