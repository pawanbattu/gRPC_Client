
import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import  QIcon
from UI.display import gRPCClient 


if __name__ == "__main__":
    try:
        app = QApplication(sys.argv)
        app.setWindowIcon(QIcon('UI/icon.png'))
        client = gRPCClient()
        client.show()
        sys.exit(app.exec_())
    except Exception as e:
        print(e)