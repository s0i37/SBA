import cutter
import sys
print(sys.version)

from PySide2.QtWidgets import QAction, QFormLayout, QWidget, QPushButton, QFileDialog, QPlainTextEdit

class MyDockWidget(cutter.CutterDockWidget):
    def __init__(self, parent, action):
        super(MyDockWidget, self).__init__(parent, action)
        self.setObjectName("MyDockWidget")
        self.setWindowTitle("Python")

        layout = QFormLayout()
        widget = QWidget()
        self.text = QPlainTextEdit()
        button_run = QPushButton("Execute")
        button_open = QPushButton("Open script")
        button_run.clicked.connect(self.run_script)
        button_open.clicked.connect(self.choose_script)
        layout.addWidget(self.text)
        layout.addWidget(button_run)
        layout.addWidget(button_open)
        widget.setLayout(layout)
        self.setWidget(widget)

    def choose_script(self):
        path_to_file, _ = QFileDialog.getOpenFileName(self, "Choose script", "", "Python script (*.py)")
        print("[+] run %s" % path_to_file)
        with open(path_to_file) as f:
            self.exec(f.read())

    def run_script(self):
        self.exec(self.text.toPlainText())

    def exec(self, code):
        exec(code, globals())



class MyCutterPlugin(cutter.CutterPlugin):
    name = "Python script runner"
    description = "This plugin allows execute any python script"
    version = "0.2"
    author = "s0i37"

    def setupPlugin(self):
        pass

    def setupInterface(self, main):
        print("[*] %s %s" % (self.name, self.version))
        action = QAction("Python", main)
        action.setCheckable(True)
        widget = MyDockWidget(main, action)
        main.addPluginDockWidget(widget, action)

    def terminate(self):
        pass

def create_cutter_plugin():
    return MyCutterPlugin()
