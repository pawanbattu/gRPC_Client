import os
import sys
import json
import random, string
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QSplitter, QTreeView, QTextEdit, QTabWidget, QPushButton,
    QLineEdit, QLabel, QFileDialog, QComboBox, QFormLayout,
    QGroupBox, QMessageBox, QPlainTextEdit, QDialog, QCheckBox,
    QSizePolicy, QScrollArea, QStackedWidget, QProgressBar,
    QTreeWidget, QAction,
    QTreeWidgetItem, QFrame, QTabBar
)
from PyQt5.QtCore import Qt, QTimer, QRegExp, QObject, QThread, pyqtSignal
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QIcon, QFont, QColor
from PyQt5.Qsci import QsciScintilla, QsciLexerJSON


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from constants import *
from executer.main import main
from UI.JSONValidatorEditor import JSONValidatorEditor
from database.queries import queries
from executer.ExecuteWorker import ExecuteWorker
from executer.helper import helper


helpercls = helper()

class CertificateDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("SSL/TLS Configuration")
        self.setMinimumWidth(600)
        self.setModal(True)
        self.cert_entries = []  # Will store {'id': db_id, 'widget': widget, ...}
        self.init_ui()

    def init_ui(self):
        try:
            self.layout = QVBoxLayout(self)

            # Scroll area
            self.scroll_area = QScrollArea()
            self.scroll_area.setWidgetResizable(True)

            # Container widget inside scroll
            self.scroll_content = QWidget()
            self.scroll_layout = QVBoxLayout(self.scroll_content)
            self.scroll_content.setLayout(self.scroll_layout)

            self.scroll_area.setWidget(self.scroll_content)
            self.layout.addWidget(self.scroll_area)

            # Add button
            add_btn = QPushButton("+ Add Certificate Set")
            add_btn.clicked.connect(self.add_cert_set)
            self.layout.addWidget(add_btn)

            # OK/Cancel buttons
            btn_layout = QHBoxLayout()
            ok_btn = QPushButton("OK")
            ok_btn.clicked.connect(self.on_ok_clicked)
            cancel_btn = QPushButton("Cancel")
            cancel_btn.clicked.connect(self.reject)
            btn_layout.addWidget(ok_btn)
            btn_layout.addWidget(cancel_btn)
            self.layout.addLayout(btn_layout)
        except Exception as e:
            helpercls.log(function_name='init_ui', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)
        

    def add_cert_set(self, cert_id=None, cert_data=None):
        try:
            """Add a new certificate set, optionally with existing data"""
            cert_widget = QFrame()
            cert_widget.setFrameShape(QFrame.StyledPanel)
            cert_widget.setFrameShadow(QFrame.Raised)
            cert_widget.setStyleSheet("""
                QFrame {
                    border-radius: 6px;
                    padding: 10px;
                    margin-bottom: 15px;
                    background-color: #fafafa;
                }
            """)

            cert_layout = QVBoxLayout(cert_widget)
            cert_layout.setContentsMargins(8, 8, 8, 8)

            # Header with delete button
            header = QWidget()
            header_layout = QHBoxLayout(header)
            header_layout.setContentsMargins(0, 0, 0, 0)
            header_layout.addStretch()

            delete_btn = QPushButton("✕")
            delete_btn.setFixedSize(40, 40)
            delete_btn.setToolTip("Delete this certificate configuration")
            delete_btn.setStyleSheet("""
                QPushButton {
                    border: none;
                    color: red;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #f5cccc;
                    border-radius: 3px;
                }
            """)
            header_layout.addWidget(delete_btn)
            cert_layout.addWidget(header)

            # Form layout
            form = QFormLayout()
            form.setHorizontalSpacing(10)
            form.setVerticalSpacing(5)

            # Form fields
            host_field = QLineEdit("localhost:50051")
            cert_path = QLineEdit()
            cert_btn = QPushButton("Browse...")
            key_path = QLineEdit()
            key_btn = QPushButton("Browse...")
            ca_path = QLineEdit()
            ca_btn = QPushButton("Browse...")
            verify_check = QCheckBox("Verify server certificate")
            verify_check.setChecked(True)

            # Add rows to form
            form.addRow("Host:", host_field)
            form.addRow("Client Certificate [CRT] File:", cert_path)
            form.addRow("", cert_btn)
            form.addRow("Client Key File:", key_path)
            form.addRow("", key_btn)
            form.addRow("CA Certificate File:", ca_path)
            form.addRow("", ca_btn)
            form.addRow("Verification:", verify_check)

            cert_layout.addLayout(form)
            self.scroll_layout.addWidget(cert_widget)

            # Connect signals
            cert_btn.clicked.connect(lambda: self.browse_file(cert_path))
            key_btn.clicked.connect(lambda: self.browse_file(key_path))
            ca_btn.clicked.connect(lambda: self.browse_file(ca_path))
            delete_btn.clicked.connect(lambda: self.remove_cert_set(cert_widget))

            # Store entry data
            entry = {
                'id': cert_id,  # None for new entries
                'widget': cert_widget,
                'host': host_field,
                'cert': cert_path,
                'key': key_path,
                'ca': ca_path,
                'verify': verify_check,
                'delete_btn': delete_btn
            }
            self.cert_entries.append(entry)

            # Populate with data if provided
            if cert_data:
                host_field.setText(cert_data.get("host", ""))
                cert_path.setText(cert_data.get("client_certificate", ""))
                key_path.setText(cert_data.get("client_key", ""))
                ca_path.setText(cert_data.get("ca_certificate", ""))
                verify_check.setChecked(cert_data.get("verify", True))
        except Exception as e:
            helpercls.log(function_name='add_cert', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)

    def remove_cert_set(self, widget):
        try:
            """Remove a certificate set from UI and mark for DB deletion"""
            reply = QMessageBox.question(
                self, 'Confirm Delete',
                'Are you sure you want to remove this certificate configuration?',
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                # Find and remove the entry
                for entry in self.cert_entries[:]:
                    if entry['widget'] == widget:
                        self.cert_entries.remove(entry)
                        
                        if isinstance(entry['id'], int):
                            main_instance = main("", "")
                            main_instance.delete_creds_entry(entry['id'])
                        break
                
                # Remove from UI
                widget.setParent(None)
                widget.deleteLater()
        except Exception as e:
            helpercls.log(function_name='remove_cert_set', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)

    def browse_file(self, target):
        try:
            filename, _ = QFileDialog.getOpenFileName(
                self,
                "Select File",
                "",
                "Certificate Files (*.pem *.crt *.key);;All Files (*)"
            )
            if filename:
                target.setText(filename)
        except Exception as e:
            helpercls.log(function_name='browse_file', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)

    def get_credentials(self):
        try:
            """Return list of certificate configs with their DB status"""
            creds = []
            for entry in self.cert_entries:
                host = entry['host'].text().strip()
                if not host:
                    QMessageBox.warning(self, "Missing Host", "One of the Host fields is empty.")
                    return None
                
                creds.append({
                    'id': entry['id'],  # None for new entries
                    'host': host,
                    'client_certificate': entry['cert'].text(),
                    'client_key': entry['key'].text(),
                    'ca_certificate': entry['ca'].text(),
                    'verify': entry['verify'].isChecked(),
                    'to_delete': False  # This would be True for entries marked for deletion
                })
            return creds
        except Exception as e:
            helpercls.log(function_name='get_credentials', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)

    def on_ok_clicked(self):
        try:
            creds = self.get_credentials()
            if creds is None:
                return 
            
            self.accept()
        except Exception as e:
            helpercls.log(function_name='on_ok_clicked', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)

    def load_certificates_from_data(self, certificates):
        try:
            """Load existing certificates from database"""
            # Clear existing
            for entry in self.cert_entries[:]:
                self.remove_cert_set(entry['widget'])
            
            # Add loaded certificates
            for cert in certificates:
                self.add_cert_set(cert_id=cert.get('creds_id'), cert_data=cert)
        except Exception as e:
            helpercls.log(function_name='load_certificates_from_data', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)

    def closeEvent(self, event):
        try:
            reply = QMessageBox.question(
                self,
                "Confirm Close",
                "Are you sure you want to close this window?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                event.accept()
            else:
                event.ignore()
        except Exception as e:
            helpercls.log(function_name='closeEvent', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)
            



class KeyValueManager(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        try:
            self.main_layout = QVBoxLayout(self)

            # Scrollable container for rows
            self.scroll_area = QScrollArea()
            self.scroll_area.setWidgetResizable(True)

            self.container_widget = QWidget()
            self.container_layout = QVBoxLayout(self.container_widget)
            self.container_layout.setAlignment(Qt.AlignTop)
            self.container_widget.setLayout(self.container_layout)

            self.scroll_area.setWidget(self.container_widget)
            self.main_layout.addWidget(self.scroll_area)

            # Add Row button
            self.add_btn = QPushButton("Add Row")
            self.add_btn.clicked.connect(self.add_row)
            self.main_layout.addWidget(self.add_btn)

            # Internal tracking of row widgets
            self.rows = []

            # Add initial row
            self.add_row()
        except Exception as e:
            helpercls.log(function_name='__init__', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)

    def add_row(self):
        try:
            row_widget = QWidget()
            row_layout = QHBoxLayout(row_widget)

            key_edit = QLineEdit()
            key_edit.setPlaceholderText("Key")

            value_edit = QLineEdit()
            value_edit.setPlaceholderText("Value")

            desc_edit = QLineEdit()
            desc_edit.setPlaceholderText("Description")

            remove_btn = QPushButton("X")
            remove_btn.setFixedSize(28, 28)

            def remove_row():
                self.container_layout.removeWidget(row_widget)
                self.rows.remove((key_edit, value_edit, desc_edit))
                row_widget.deleteLater()

            remove_btn.clicked.connect(remove_row)

            row_layout.addWidget(key_edit)
            row_layout.addWidget(value_edit)
            row_layout.addWidget(desc_edit)
            row_layout.addWidget(remove_btn)

            self.container_layout.addWidget(row_widget)
            self.rows.append((key_edit, value_edit, desc_edit))
        except Exception as e:
            helpercls.log(function_name='add_row', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)

    def get_data(self):
        try:
            """Return list of dicts with key, value, and description from each row."""
            return [
                {
                    "key": key.text().strip(),
                    "value": value.text().strip(),
                    "description": desc.text().strip()
                }
                for key, value, desc in self.rows
            ]
        except Exception as e:
            helpercls.log(function_name='get_data', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)


class AuthorizationWidget(QWidget):
    """Authorization UI with multiple auth types and dynamic fields."""

    def __init__(self):
        super().__init__()
        try:
            layout = QVBoxLayout()
            layout.setContentsMargins(5, 5, 5, 5)
            layout.setSpacing(10)
            self.current_selected_auth = None

            # Auth type dropdown
            self.auth_type_combo = QComboBox()
            self.auth_type_combo.addItems([
                "No Auth",
                "API Key",
                "Bearer Token",
                "Basic Auth",
                "OAuth2"
            ])
            self.auth_type_combo.currentIndexChanged.connect(self.on_auth_type_changed)

            layout.addWidget(QLabel("Auth Type:"))
            layout.addWidget(self.auth_type_combo)

            # Stacked widget for different auth options
            self.stacked = QStackedWidget()

            # No Auth (empty widget)
            self.no_auth_widget = QWidget()
            self.stacked.addWidget(self.no_auth_widget)

            # API Key widget
            self.api_key_widget = QWidget()
            api_layout = QFormLayout()
            self.api_key_name = QLineEdit()
            self.api_key_name.setText('x-api-key')
            self.api_key_value = QLineEdit()
            # self.api_key_add_to = QComboBox()
            # self.api_key_add_to.addItems(["Header", "Query Params"])
            api_layout.addRow("Key Name:", self.api_key_name)
            api_layout.addRow("Key Value:", self.api_key_value)
            # api_layout.addRow("Add To:", self.api_key_add_to)
            self.api_key_widget.setLayout(api_layout)
            self.stacked.addWidget(self.api_key_widget)

            # Bearer Token widget
            self.bearer_widget = QWidget()
            bearer_layout = QFormLayout()
            self.bearer_token = QLineEdit()
            bearer_layout.addRow("Token:", self.bearer_token)
            self.bearer_widget.setLayout(bearer_layout)
            self.stacked.addWidget(self.bearer_widget)

            # Basic Auth widget
            self.basic_auth_widget = QWidget()
            basic_layout = QFormLayout()
            self.basic_username = QLineEdit()
            self.basic_password = QLineEdit()
            self.basic_password.setEchoMode(QLineEdit.Password)
            basic_layout.addRow("Username:", self.basic_username)
            basic_layout.addRow("Password:", self.basic_password)
            self.basic_auth_widget.setLayout(basic_layout)
            self.stacked.addWidget(self.basic_auth_widget)

            # OAuth2 widget
            self.oauth2_widget = QWidget()
            oauth2_layout = QFormLayout()
            self.oauth2_client_id = QLineEdit()
            self.oauth2_client_secret = QLineEdit()
            self.oauth2_client_secret.setEchoMode(QLineEdit.Password)
            self.oauth2_token_url = QLineEdit()
            self.oauth2_scope = QLineEdit()
            oauth2_layout.addRow("Client ID:", self.oauth2_client_id)
            oauth2_layout.addRow("Client Secret:", self.oauth2_client_secret)
            oauth2_layout.addRow("Token URL:", self.oauth2_token_url)
            oauth2_layout.addRow("Scope:", self.oauth2_scope)
            self.oauth2_widget.setLayout(oauth2_layout)
            self.stacked.addWidget(self.oauth2_widget)

            layout.addWidget(self.stacked)

            self.setLayout(layout)
        except Exception as e:
            helpercls.log(function_name='__init__', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)

    def on_auth_type_changed(self, index):
        try:
            self.current_selected_auth = self.auth_type_combo.currentText()
            self.stacked.setCurrentIndex(index)
        except Exception as e:
            helpercls.log(function_name='on_auth_type_changed', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)

    def get_auth_values(self):
        try:
            auth_type = self.current_selected_auth

            # if auth_type == "No Auth":
            #     return {"auth_type": "none"}

            if auth_type == "API Key":
                return {
                    "auth_type": "api_key",
                    "key_name": self.api_key_name.text(),
                    "key_value": self.api_key_value.text(),
                    # "add_to": self.api_key_add_to.currentText(),  # if needed
                }

            elif auth_type == "Bearer Token":
                return {
                    "auth_type": "bearer_token",
                    "token": self.bearer_token.text()
                }

            elif auth_type == "Basic Auth":
                return {
                    "auth_type": "basic_auth",
                    "username": self.basic_username.text(),
                    "password": self.basic_password.text()
                }

            elif auth_type == "OAuth2":
                return {
                    "auth_type": "oauth2",
                    "client_id": self.oauth2_client_id.text(),
                    "client_secret": self.oauth2_client_secret.text(),
                    "token_url": self.oauth2_token_url.text(),
                    "scope": self.oauth2_scope.text()
                }

            return {"auth_type": "none"}
        except Exception as e:
            helpercls.log(function_name='get_auth_values', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)


    


class GRPCTab(QWidget):
    def __init__(self, tab_widget):
        super().__init__()
        try:
            self.init_tab_ui()
            self.ssl_credentials = None
            self.tab_data = {}
            self.tab_widget = tab_widget
            main_instance = main(None, {}) 
            certsdata = main_instance.get_creds_db()
            if (certsdata):
                self.tab_data['ssl'] = certsdata
        except Exception as e:
            helpercls.log(function_name='__init__', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)
        
    def request_editor_widget(self):
        try:
            editor = QsciScintilla()

            font = QFont("Consolas", 9)
            editor.setFont(font)

            # Set lexer
            lexer = QsciLexerJSON()
            lexer.setDefaultFont(font)

            # JSON lexer actually has these style constants:
            # 0: Default
            # 1: Comment
            # 2: Number
            # 3: String
            # 4: Property (key)
            # 5: Keyword (true/false/null)
            # 6: Operator
            # 7: Error

            # Color scheme
            lexer.setColor(QColor("#c9184a"), 4)  # Property (keys) in light blue
            lexer.setColor(QColor("#CE9178"), 3)  # Strings in light orange
            lexer.setColor(QColor("#bc6c25"), 2)  # Numbers in soft green
            lexer.setColor(QColor("#569CD6"), 6)  # Operators in blue
            lexer.setColor(QColor("#C586C0"), 5)  # Keywords (true/false/null) in purple
            lexer.setColor(QColor("#D4D4D4"), 0)  # Default text

            editor.setLexer(lexer)

            # Editor appearance
            editor.setMarginsFont(font)
            editor.setMarginWidth(0, "0000")
            editor.setMarginLineNumbers(0, True)
            editor.setMarginBackgroundColor(0, QColor("#1E1E1E"))

            # Current line highlighting
            # editor.setCaretLineVisible(True)
            # editor.setCaretLineBackgroundColor(QColor("#2D2D2D"))

            # Editor colors
            editor.setPaper(QColor("#1E1E1E"))
            editor.setColor(QColor("#D4D4D4"))

            return editor
        except Exception as e:
            helpercls.log(function_name='request_editor_widget', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)
    

    def init_tab_ui(self):
        try:
            layout = QHBoxLayout()
            left_panel = self.create_left_panel()
            right_panel = self.create_right_panel()

            splitter = QSplitter(Qt.Horizontal)
            splitter.addWidget(left_panel)
            splitter.addWidget(right_panel)
            splitter.setSizes([350, 850])

            layout.addWidget(splitter)
            self.setLayout(layout)
        except Exception as e:
            helpercls.log(function_name='init_tab_ui', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)

    def create_left_panel(self):
        try:
            # Main Tab Widget
            main_tabs = QTabWidget()

            # --------- Tab 1: Configuration UI ---------
            left_panel = QWidget()
            layout = QVBoxLayout()
            layout.setSpacing(3)
            layout.setContentsMargins(5, 5, 5, 5)

            connection_group = QGroupBox("Connection")
            connection_layout = QFormLayout()
            self.host_input = QLineEdit("localhost:50051")
            self.ssl_checkbox = QComboBox()
            self.ssl_checkbox.addItems(["Insecure", "SSL/TLS"])
            self.certificate_btn = QPushButton("Configure Certificates...")
            self.certificate_btn.clicked.connect(self.show_certificate_dialog)
            connection_layout.addRow("Host:", self.host_input)
            connection_layout.addRow("Security:", self.ssl_checkbox)
            connection_layout.addRow("", self.certificate_btn)
            connection_group.setLayout(connection_layout)

            config_tabs = QTabWidget()

            proto_tab = QWidget()
            proto_layout = QVBoxLayout()
            self.proto_path = QLineEdit()
            self.proto_browse_btn = QPushButton("Browse...")
            self.proto_browse_btn.clicked.connect(lambda: self.browser_file_proto(self.proto_browse_btn))
            self.import_paths = QPlainTextEdit()
            load_proto_btn = QPushButton("Import from Proto File")
            load_proto_btn.clicked.connect(self.list_services)
            use_reflection_btn = QPushButton("Use Reflection")
            use_reflection_btn.clicked.connect(self.list_services)
            proto_layout.addWidget(QLabel("Proto File Path:"))
            proto_layout.addWidget(self.proto_path)
            proto_layout.addWidget(self.proto_browse_btn)
            proto_layout.addWidget(QLabel("Additional Import Paths:"))
            proto_layout.addWidget(self.import_paths)
            proto_layout.addWidget(load_proto_btn)
            proto_layout.addWidget(use_reflection_btn)
            proto_tab.setLayout(proto_layout)

            self.metadata_tab = QWidget()
            metadata_layout = QVBoxLayout()
            self.metadata_container = QVBoxLayout()
            scroll_meta = QScrollArea()
            scroll_widget = QWidget()
            scroll_widget.setLayout(self.metadata_container)
            scroll_meta.setWidget(scroll_widget)
            scroll_meta.setWidgetResizable(True)

            metadata_layout.addWidget(scroll_meta)
            self.metadata_tab.setLayout(metadata_layout)

            self.auth_tab = AuthorizationWidget()
            self.metadata_tab = KeyValueManager()
            config_tabs.addTab(proto_tab, "Proto")
            config_tabs.addTab(self.metadata_tab, "Meta Data")
            config_tabs.addTab(self.auth_tab, "Authorization")

            layout.addWidget(connection_group)
            layout.addWidget(config_tabs)

            left_panel.setLayout(layout)

            # --------- Tree Panel (Service/Method Browser) ---------
            
            tree_panel = QWidget()
            tree_layout = QVBoxLayout()

            self.tree_widget = QTreeWidget()
            self.tree_widget.setHeaderHidden(True)  # Hide headers

            tree_layout.addWidget(self.tree_widget)
            tree_panel.setLayout(tree_layout)
            main_instance = main('', '')

            # Utility: create a row with label + delete
            def make_item_widget(item, text, id = ""):
                container = QWidget()
                hbox = QHBoxLayout(container)
                hbox.setContentsMargins(2, 0, 2, 0)

                label = QLabel(text)
                hbox.addWidget(label)

                delete_btn = QPushButton("✕")
                delete_btn.setFixedSize(20, 20)
                delete_btn.setToolTip("Delete")
                delete_btn.setStyleSheet("""
                    QPushButton {
                        border: none;
                        color: red;
                        font-weight: bold;
                    }
                    QPushButton:hover {
                        background-color: #f5cccc;
                        border-radius: 3px;
                    }
                """)
                hbox.addWidget(delete_btn)

                # Store text
                item.setData(0, Qt.UserRole, id)
                
                # Delete action
                def remove_item():
                    hidden_id = item.data(0, Qt.UserRole) 
                    
                    parent = item.parent()
                    if (main_instance.delete_tab_id(hidden_id)):
                        if parent:
                            parent.removeChild(item)
                        else:
                            idx = self.tree_widget.indexOfTopLevelItem(item)
                            self.tree_widget.takeTopLevelItem(idx)
                    else:
                        QMessageBox.warning(self, "Warning", "Error while deleting")
                        return False

                delete_btn.clicked.connect(remove_item)

                self.tree_widget.setItemWidget(item, 0, container)

            self.tree_widget.itemClicked.connect(self.oncollection_item_clicked)

            # Example: Service with methods
            service_item = QTreeWidgetItem(self.tree_widget)
            make_item_widget(service_item, "MyCollection")
            

            tabs_data = main_instance.get_all_tabs()
            if (tabs_data and isinstance(tabs_data, list) and len(tabs_data) > 0):
                for tab_name in tabs_data:
                    method_item = QTreeWidgetItem(service_item)
                    make_item_widget(method_item, tab_name['tab_name'], tab_name['id'])

            service_item.setExpanded(True)

            # --------- Add both tabs to main_tabs ---------
            main_tabs.addTab(left_panel, "Configuration")
            main_tabs.addTab(tree_panel, "Collection")

            return main_tabs
        except Exception as e:
            helpercls.log(function_name='create_left_panel', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)
    

    def oncollection_item_clicked(self, item, column):
        try:
            widget = self.tree_widget.itemWidget(item, column)
            if widget:
                
                label = widget.findChild(QLabel)
                if label:
                    main_instance = main('', '')
                    tab_id = item.data(0, Qt.UserRole)
                    if (not isinstance(tab_id, int)):
                        QMessageBox.critical(self, "Error", "Error while getting tab id please try again")
                        return False
                    
                    tab_data = main_instance.get_tab_all_data(tab_id)
                    meta_data = main_instance.get_meta_by_tab_id(tab_id)
            
                    if (not tab_data and not isinstance(tab_data, list) and not isinstance(tab_data[0], dict)):
                        QMessageBox.critical(self, "Error", "Error while getting tab data please try again")
                        return False
                    
                    self.create_and_populate_tab(tab_data[0], meta_data)
                    
        except Exception as e:
            helpercls.log(function_name='oncollection_item_clicked', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)
                
        

    def create_and_populate_tab(self, tab_data, meta_data = {}):
        try:
        
            main_window = self.window()
            if hasattr(main_window, 'create_new_tab'):
                # Create a new tab
                
                tab_name = tab_data.get('tab_name') if tab_data else None
                tab_id = tab_data.get('tab_id') if tab_data else None

                # ✅ Directly get the created tab
                new_tab = main_window.create_new_tab(tab_name, tab_id)

                # ✅ Now you can access its methods/properties easily
                
                # Example: Populate tab with data
                new_tab.populate_tab_with_data(tab_data, meta_data)
                #self.populate_tab_with_data(current_tab, tab_data, meta_data)
        except Exception as e:
            helpercls.log(function_name='create_and_populate_tab', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)
    
    def populate_tab_with_data(self, tab_data, meta_data):
        try:
            """Populate a tab widget with data from database"""
            
            # Extract data from tab_data (assuming it's a dictionary)
            if not tab_data:
                return
            
            meta = None
            if (meta_data and isinstance(meta_data, list) and isinstance(meta_data[0], dict)):
                meta = meta_data[0]

            # Set host
            if 'tab_host' in tab_data:
                self.host_input.setText(tab_data['tab_host'])
        
            
            # Set proto path if available
            if 'proto_file_path' in tab_data:
                self.proto_path.setText(tab_data['proto_file_path'])
            
            # Set import paths if available
            if 'proto_additional_path' in tab_data:
                self.import_paths.setPlainText(tab_data['proto_additional_path'])
            
            # Set method name in search box if available
            if 'method_name' in tab_data:
                self.services_search_box.setText(tab_data['method_name'])

            
            # Set services data if available
            if 'services_data' in tab_data:
                self.tab_data['services'] = tab_data['services_data']
            
            # Populate metadata tab
            if meta_data and hasattr(self.metadata_tab, 'rows'):
                # Clear existing rows
                for row in self.metadata_tab.rows[:]:
                    self.metadata_tab.container_layout.removeWidget(row[0].parent())
                    row[0].parent().deleteLater()
                    self.metadata_tab.rows.remove(row)
                
                # Add rows from meta_data
                for meta_item in meta_data:
                    self.metadata_tab.add_row()
                    new_row = self.metadata_tab.rows[-1]
                    new_row[0].setText(meta_item.get('name', ''))
                    new_row[1].setText(meta_item.get('value', ''))
                    new_row[2].setText(meta_item.get('description', ''))
            
            # Populate auth data if available
            if 'auth_data' in tab_data and tab_data['auth_data']:
                auth_data = json.loads(tab_data['auth_data'])
                auth_type = tab_data.get('auth_name', 'none')
                
                # Set auth type in combo box
                index = self.auth_tab.auth_type_combo.findText(
                    self.get_auth_type_display_name(auth_type)
                )
                if index >= 0:
                    self.auth_tab.auth_type_combo.setCurrentIndex(index)
                    self.auth_tab.on_auth_type_changed(index)
                
                # Populate auth fields based on type
                if auth_type == "api_key":
                    self.auth_tab.api_key_name.setText(auth_data.get('key_name', ''))
                    self.auth_tab.api_key_value.setText(auth_data.get('key_value', ''))
                elif auth_type == "bearer_token":
                    self.auth_tab.bearer_token.setText(auth_data.get('token', ''))
                elif auth_type == "basic_auth":
                    self.auth_tab.basic_username.setText(auth_data.get('username', ''))
                    self.auth_tab.basic_password.setText(auth_data.get('password', ''))
                elif auth_type == "oauth2":
                    self.auth_tab.oauth2_client_id.setText(auth_data.get('client_id', ''))
                    self.auth_tab.oauth2_client_secret.setText(auth_data.get('client_secret', ''))
                    self.auth_tab.oauth2_token_url.setText(auth_data.get('token_url', ''))
                    self.auth_tab.oauth2_scope.setText(auth_data.get('scope', ''))
            
            # Set request data if available
            if 'request_message' in tab_data and tab_data['request_message']:
                try:
                    # Parse and format JSON for better display
                    parsed_json = json.loads(tab_data['request_message'])
                    formatted_json = json.dumps(parsed_json, indent=2)
                    self.request_editor.setText(formatted_json)
                except json.JSONDecodeError:
                    # If not valid JSON, display as plain text
                    self.request_editor.setText(tab_data['request_message'])
            
            self.list_services()
        except Exception as e:
            helpercls.log(function_name='populate_tab_with_data', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)
    

    def get_auth_type_display_name(self, auth_type):
        try:
            """Convert internal auth type to display name"""
            mapping = {
                'none': 'No Auth',
                'api_key': 'API Key',
                'bearer_token': 'Bearer Token',
                'basic_auth': 'Basic Auth',
                'oauth2': 'OAuth2'
            }
            return mapping.get(auth_type, 'No Auth')
        except Exception as e:
            helpercls.log(function_name='get_auth_type_display_name', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)

    
    def browser_file_proto(self, target):
        try:
            filename, _ = QFileDialog.getOpenFileName(
                self, 
                "Select File", 
                "", 
                "Proto Files (*.proto);;All Files (*)"
            )
            if filename:
                target.setText(filename)
        except Exception as e:
            helpercls.log(function_name='browser_file_proto', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)

    def create_right_panel(self):
        try:
            right_panel = QWidget()

            self.services_search_box = QLineEdit()
            self.services_search_box.setPlaceholderText("Search...")
            self.services_search_box.textChanged.connect(self.search_tree)
            self.services_tree = QTreeView()
            self.services_model = QStandardItemModel()
            self.services_tree.setModel(self.services_model)
            self.services_tree.setHeaderHidden(True)

            self.request_editor = JSONValidatorEditor()
            self.response_viewer = JSONValidatorEditor()

            # Tab widget containing Request and Response
            self.body_tabs = QTabWidget()
            self.body_tabs.addTab(self.request_editor, "Request")
            self.body_tabs.addTab(self.response_viewer, "Response")

            # Combine services tree and request/response tabs in a vertical splitter
            tree_and_body_splitter = QSplitter(Qt.Vertical)
            tree_widget = QWidget()
            tree_layout = QVBoxLayout()
            tree_layout.setContentsMargins(0, 0, 0, 0)
            tree_layout.setSpacing(0)
            tree_layout.addWidget(self.services_search_box)
            tree_layout.addWidget(self.services_tree)
            tree_widget.setLayout(tree_layout)

            tree_and_body_splitter.addWidget(tree_widget)
            tree_and_body_splitter.addWidget(self.body_tabs)
            tree_and_body_splitter.setSizes([300, 400])

            btn_layout = QHBoxLayout()
            auto_populate_btn = QPushButton("Auto-Populate")
            auto_populate_btn.clicked.connect(self.auto_populate)
            cancel_request_btn = QPushButton("Cancel Request")
            save_request_btn = QPushButton("Save Tab")
            execute_btn = QPushButton("Execute Request")
            execute_btn.clicked.connect(self.execute_request)
            #cancel_request_btn.clicked.connect(self.auto_populate)
            save_request_btn.clicked.connect(self.save_tab_data)
            btn_layout.addWidget(auto_populate_btn)
            btn_layout.addWidget(save_request_btn)
            #btn_layout.addWidget(cancel_request_btn)
            btn_layout.addWidget(execute_btn)

            layout = QVBoxLayout()
            layout.addWidget(tree_and_body_splitter)
            layout.addLayout(btn_layout)
            self.init_visible_progress(layout)


            right_panel.setLayout(layout)
            return right_panel
        except Exception as e:
            helpercls.log(function_name='create_right_panel', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)
    
    def show_certificate_dialog(self):
        try:
            dialog = CertificateDialog(self)
            main_instance = main(None, {})
            
            certsdata = main_instance.get_creds_db()
            if (certsdata):
                self.tab_data['ssl'] = certsdata
            if 'ssl' in self.tab_data.keys():
                dialog.load_certificates_from_data(self.tab_data['ssl'])
                
            if dialog.exec_():
                self.ssl_credentials = dialog.get_credentials()
                self.tab_data['ssl'] = self.ssl_credentials if self.ssl_credentials is not None else {}
                print(self.tab_data['ssl'])
                if (isinstance(self.tab_data['ssl'], list) and len(self.tab_data['ssl']) > 0):
                    for certs in self.tab_data['ssl']:
                        if (isinstance(certs, dict) and (certs['client_certificate'] != '' or certs['client_key'] != '' or certs['ca_certificate'] != '') and not certs['id']):
                            main_instance.insert_creds(certs)
                        if (isinstance(certs, dict) and (certs['client_certificate'] != '' or certs['client_key'] != '' or certs['ca_certificate'] != '') and certs['id']):
                            if not main_instance.update_creds_entry(certs['id'], certs):
                                QMessageBox.warning(self, "Warning", "Error Occured while updating")
                                return False
        except Exception as e:
            helpercls.log(function_name='show_certificate_dialog', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)
                        

    def highlightBlock(self, text):
        try:
            for key, value in self.json_data.items():
                if isinstance(value, self.target_type):
                    pattern = f'"{key}"'  # matches the key in quotes
                    expression = QRegExp(pattern)
                    index = expression.indexIn(text)
                    while index >= 0:
                        length = expression.matchedLength()
                        self.setFormat(index, length, self.highlight_format)
                        index = expression.indexIn(text, index + length)
        except Exception as e:
            helpercls.log(function_name='highlightBlock', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)

    def get_my_tab_name_and_data(self):
        try:
            index = self.tab_widget.indexOf(self)
            if (self.tab_widget.tabText(index)):
                return {'tab_name' : self.tab_widget.tabText(index), 'tab_id' : self.tab_widget.tabBar().tabData(index)}
            else:
                return {'tab_name' : ''.join(random.choices(string.ascii_letters + string.digits, k=8)) , 'tab_id' : ''}
        except Exception as e:
            helpercls.log(function_name='get_my_tab_name_and_data', args=[], exception=e)
            QMessageBox.warning(self, "Something went wrong", e)



    def save_tab_data(self):
        try:
            tab_data = self.get_my_tab_name_and_data()

            tab_id = 0
            if (isinstance(tab_data, dict) and 'tab_name' in tab_data and 'tab_id' in tab_data):
                tab_name = tab_data['tab_name']
                tab_id = tab_data['tab_id']
                
            method_name = None
            if (self.services_search_box.text()):
                method_name = self.services_search_box.text()
            
            data = self.get_data()

            if (not isinstance(data, dict)):
                QMessageBox.critical(self, "Error", "Error while saving please try again")
                return False

            request_data_input = self.request_editor.text()
            request_data = ""
            if (request_data_input):
                parsed = json.loads(request_data_input)
                request_data = json.dumps(parsed, separators=(',', ':'))

            
            main_instance = main("", "")
            res = main_instance.save_tab_data(tab_name, method_name, data, request_data, '', tab_id)
            if (not res):
                QMessageBox.critical(self, "Error", "Error while saving please try again")
                return False    
            else:
                QMessageBox.information(None, "Success", "Operation completed successfully!")

            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"save_tab_data: {str(e)}")
            helpercls.log(function_name='get_my_tab_name_and_data', args=[], exception=e)
            

    def list_services(self):
        try:
            sender = self.sender() 
            btn = None

            if sender:
                if isinstance(sender, QPushButton) or isinstance(sender, QAction):
                    btn = sender.text()
    
            proto_path_text = proto_import_path = None
            if (self.proto_path.text()):
                proto_path_text = self.proto_path.text()
            secure_data = {}
            if (btn == "Import from Proto File" or (proto_path_text and btn is None)):
                
                if (not os.path.exists(proto_path_text)):
                    QMessageBox.critical(self, "Error", f"Proto Path does not exists {str(proto_path_text)}")
                    return False
                proto_import_path = self.import_paths.toPlainText()

            host = self.host_input.text()
        
            if not host:
                QMessageBox.warning(self, "Warning", "Please specify host")
                return False
            if self.ssl_checkbox.currentText() == "SSL/TLS":
                secure = 1
                if 'ssl' not in self.tab_data.keys():
                    QMessageBox.warning(self, "Warning", "Cert file not passed")
                    return False
                secure_data = self.tab_data['ssl'] if self.tab_data['ssl'] is not None else {}        

            self.show_progress()
            self.update_bar(20)
            main_instance = main(host, secure_data)
            
            get_servicesres = main_instance.get_services(proto_path_text, proto_import_path)
            
            self.hide_progress()
            if (get_servicesres['error']):
                
                message_value = (get_servicesres.get('data', {}).get('error', {}).get('details', {}).get('obj', {}).get('error', {}).get('message'))
                QMessageBox.critical(self, "Error", f"Error occured while importing from proto {message_value}")
                return False
            
            serviceskeys = get_servicesres['data'].keys()
            if (get_servicesres['data'] and not len(serviceskeys) >= 1):
                QMessageBox.warning(self, "Warning", "No service found")
                return False
        
            # Clear existing items
            self.services_model.clear()
            data_to_add = {}
            for services in get_servicesres['data']:
    
                service_item = QStandardItem(services)
                service_item.setFlags(service_item.flags() & ~Qt.ItemIsSelectable)
                
                for method in get_servicesres['data'][services]['methods']:
                    method_item = QStandardItem(method)
                    method_item.setFlags(method_item.flags() | Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                    service_item.appendRow(method_item)
                    data_to_add[method] = services
                self.services_model.appendRow(service_item)
            self.tab_data['services'] = data_to_add

            self.services_tree.expandAll()
            self.services_tree.selectionModel().selectionChanged.connect(self.update_textbox_from_selection)
        except Exception as e:
            self.hide_progress()
            QMessageBox.critical(self, "Error", f"Failed to use reflection: {str(e)}")
            helpercls.log(function_name='list_services', args=[], exception=e)


    def auto_populate(self):
        try:
            data = self.get_data()
            main_instance = main(data['host'], data['secure_data'])
            if (not data):
                QMessageBox.critical(self, "Error", "Failed to use autopopulate")
                return False
            
            method_name = self.services_search_box.text() 
            if (not method_name):
                QMessageBox.critical(self, "Error", "Please choose service name")
                return False

            if ('services' not in self.tab_data and len(self.tab_data['services']) == 0):
                QMessageBox.critical(self, "Error", "something went wrong please try again")
                return False
            
            mapped_service_name = self.tab_data['services'][method_name]
            if (not mapped_service_name):
                QMessageBox.critical(self, "Error", "something went wrong please try again")
                return False
            self.show_progress()
            self.update_bar(20)
            get_message_auto_populate = main_instance.get_message_auto_populate(data['proto_path'], data['proto_import_path'], mapped_service_name, method_name)
            self.update_bar(100)
            self.hide_progress()
            if (get_message_auto_populate['error']):
                QMessageBox.critical(self, "Error", f"Something went wrong : {get_message_auto_populate['data']}")
                return False
            
            if (get_message_auto_populate['data'] is None or get_message_auto_populate['data'] is None):
                QMessageBox.critical(self, "Error", "Something went wrong")
                return False
            
            
            self.request_editor.setText((json.dumps(get_message_auto_populate['data'], indent=2)))
            self.body_tabs.setCurrentWidget(self.request_editor)

        except Exception as e:
            self.hide_progress()
            QMessageBox.critical(self, "Error", f"Failed to auto_populate: {str(e)}")
            helpercls.log(function_name='auto_populate', args=[], exception=e)


    def execute_request(self):
        try:
            data = self.get_data()
            
            if (not data):
                QMessageBox.critical(self, "Error", "Failed to get data")
                return False
            
            method_name = self.services_search_box.text() 
            if (not method_name):
                QMessageBox.critical(self, "Error", "Please choose method name")
                return False
            
            if ('services' not in self.tab_data or not isinstance(self.tab_data['services'], dict)):
                QMessageBox.critical(self, "Error", f"Sevices are not loaded : {method_name}")
                return False
            
            if (method_name not in self.tab_data['services']):
                QMessageBox.critical(self, "Error", f"Method is not a part of proto : {method_name}")
                return False

            mapped_service_name = self.tab_data['services'][method_name]
            if (not mapped_service_name):
                QMessageBox.critical(self, "Error", "something went wrong please try again")
                return False
            
            #request_data_input = self.request_editor.toPlainText()
            request_data_input = self.request_editor.text()

            if (not len(str(request_data_input)) > 0):
                QMessageBox.critical(self, "Error", "Request data is empty")
                return False
            
            # Validate JSON
            try:
                parsed = json.loads(request_data_input)
            except json.JSONDecodeError:
                QMessageBox.critical(self, "Error", "Invalid JSON in request")
                return False

            request_data = json.dumps(parsed, separators=(',', ':'))
            
            main_instance = main(data['host'], data['secure_data'])

            self.show_progress()
            self.update_bar(50)

            # Setup QThread
            self.thread = QThread()
            self.worker = ExecuteWorker(data['host'], data['secure_data'], data['proto_path'], data['proto_import_path'], data['meta_data'], mapped_service_name, method_name, request_data, data['auth_data'])
            self.worker.moveToThread(self.thread)
            # Setup QThread

            # Connect signals
            self.thread.started.connect(self.worker.run)
            self.worker.finished.connect(self.on_execute_finished)
            self.worker.error.connect(self.on_execute_error)

            # Cleanup signals
            self.worker.finished.connect(self.thread.quit)
            self.worker.finished.connect(self.worker.deleteLater)
            self.thread.finished.connect(self.thread.deleteLater)

            self.thread.start()

        except Exception as e:
            self.hide_progress()
            QMessageBox.critical(self, "Error", f"Failed to execute request: {str(e)}")
            helpercls.log(function_name='execute_request', args=[], exception=e)

    def on_execute_finished(self, get_execute_request):
        try:
            if (get_execute_request['error']):
                self.hide_progress()
                json_str = json.dumps(get_execute_request['data'], indent=2)
                self.response_viewer.settext(str(json_str))
                self.body_tabs.setCurrentWidget(self.response_viewer)
                
                return False
            
            json_str = json.dumps(get_execute_request['data'], indent=2)
            self.response_viewer.settext(str(json_str))
            self.update_bar(100)
            self.body_tabs.setCurrentWidget(self.response_viewer)
        except Exception as e:
            self.hide_progress()
            QMessageBox.critical(self, "Error", f"Something went wrong : {str(e)}")
            helpercls.log(function_name='on_execute_finished', args=[], exception=e)

    def on_execute_error(self, error_msg):
        self.hide_progress()
        QMessageBox.warning(self, "Warning", f"Something went wrong while executing the request \n {error_msg}")
        return False


    def get_data(self):
        try:
            proto_path = proto_import_path = secure_data = meta_data = auth_data = None
            
            proto_path  = self.proto_path.text() if self.proto_path.text() else None
            proto_import_path = self.import_paths.toPlainText() if self.proto_path.text() else None

            host = self.host_input.text()
            secure = 0
            
            if not host:
                QMessageBox.warning(self, "Warning", "Please specify host")
                return False
            if self.ssl_checkbox.currentText() == "SSL/TLS":
                secure = 1
                if 'ssl' not in self.tab_data.keys():
                    QMessageBox.warning(self, "Warning", "Cert file not passed")
                    return False
                secure_data = self.tab_data['ssl'] if self.tab_data['ssl'] is not None else {}
                certs_asper_host = {}

                if (isinstance(secure_data, list) and len(secure_data) > 0):
                    for certs in secure_data:
                        if certs['host'] == host:
                            certs_asper_host = certs
                secure_data = certs_asper_host
                

            metadata_tab = self.metadata_tab.get_data()
            if metadata_tab:
                meta_data = metadata_tab

            auth_data_values = self.auth_tab.get_auth_values()
            

            if (isinstance(auth_data_values, dict) and len(auth_data_values) > 0):
                auth_data = auth_data_values

            '''
            As now no way to detect the whether it is reflection or proto import so we will check if proto path is there then we will assume it

            creds_as_per_host = {}
            if (isinstance(self.creds, dict) and len(self.creds) > 0):
                for certs in self.creds:
                    if self.host == self.creds['host']:
            '''
            response = {'proto_path' : proto_path, 'proto_import_path' : proto_import_path, 'host' : host, 'secure' : secure, 'secure_data' : secure_data, 'meta_data' : meta_data, 'auth_data' : auth_data}

            return response
        
        
        except Exception as e:
            self.hide_progress()
            QMessageBox.critical(self, "Error", f"Something went wrong : {str(e)}")
            helpercls.log(function_name='get_data', args=[], exception=e)


    def search_tree(self, text):
        try:
            text = text.lower()
            root_item = self.services_model.invisibleRootItem()
            
            # Dynamically get all top-level items (parents) if not already stored
            
            self.service_names = []
            for row in range(root_item.rowCount()):
                parent = root_item.child(row)
                self.service_names.append(parent)

            for parent in self.service_names:
                parent_index = self.services_model.indexFromItem(parent)
                parent_visible = text in parent.text().lower()
                any_child_visible = False

                for row in range(parent.rowCount()):
                    child = parent.child(row)
                    child_index = self.services_model.indexFromItem(child)
                    match = text in child.text().lower()
                    self.services_tree.setRowHidden(row, parent_index, not match)
                    any_child_visible |= match

                # Show/hide parent based on match
                parent_row = parent.row()
                self.services_tree.setRowHidden(parent_row, root_item.index(), not (parent_visible or any_child_visible))

            self.services_tree.expandAll()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Something went wrong : {str(e)}")
            helpercls.log(function_name='search_tree', args=[], exception=e)

    def update_textbox_from_selection(self, selected, _deselected):
        try:
            if not selected.indexes():
                return
            index = selected.indexes()[0]
            item = self.services_model.itemFromIndex(index)
            if item and item.flags() & Qt.ItemIsSelectable:
                self.services_search_box.setText(item.text())
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Something went wrong : {str(e)}")
            helpercls.log(function_name='update_textbox_from_selection', args=[], exception=e)

    '''Progress Bar'''
    def init_visible_progress(self, right_layout):
        """Initialize progress bar with guaranteed visibility"""
        # Create progress bar with visible defaults
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        
        # Ensure visibility settings
        self.progress_bar.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.progress_bar.setMinimumHeight(25)  # Make sure it's tall enough to see
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setAlignment(Qt.AlignCenter)
        
        # Style sheet for guaranteed visibility
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #d3d3d3;
                border-radius: 5px;
                background: #f0f0f0;
                padding: 1px;
                height: 25px;
            }
            QProgressBar::chunk {
                background: #4CAF50;
                width: 10px;
                border-radius: 3px;
            }
        """)
        
        # Add to layout with stretch control
        index = right_layout.count()  # This gives you the end position
        right_layout.insertWidget(index, self.progress_bar)  # Equivalent to addWidget()
        #self.request_layout.insertWidget(-1, self.progress_bar)  # Position at index 2
        
        self.progress_bar.hide()  # Start hidden
        
        # Progress control variables
        self.progress_timer = QTimer()
        self.progress_timer.timeout.connect(self.update_progress)
        
    def show_progress(self):
        """Make progress bar visible with visual feedback"""
        self.progress_bar.show()
        self.progress_bar.repaint()  # Force immediate redraw
        QApplication.processEvents()  # Process UI events
        
    def hide_progress(self):
        """Hide progress bar"""
        self.progress_bar.hide()
        
    def start_progress_animation(self, duration=2000):
        """Demo animation to verify visibility"""
        self.show_progress()
        self.progress_bar.setValue(0)
        self.progress_timer.stop()
        
        # Animate from 0-100% over specified duration
        steps = 100
        interval = duration // steps
        self.progress_timer.start(interval)
        
    def update_progress(self):
        """Timer callback for progress animation"""
        current = self.progress_bar.value()
        if current < 100:
            self.progress_bar.setValue(current + 1)
        else:
            self.progress_timer.stop()
            QTimer.singleShot(500, self.hide_progress)  # Hide after completion

    def update_bar(self, value):
        self.progress_bar.setValue(value)
        QApplication.processEvents()  # Update UI



class gRPCClient(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("gRPC Client")
        self.setWindowIcon(QIcon('UI/icon.png')) 
        screen = QApplication.primaryScreen()
        rect = screen.availableGeometry()
        self.setGeometry(rect) 
        self.tab_counter = 1
        self.init_ui()

    def init_ui(self):
        try:
            main_widget = QWidget()
            main_layout = QHBoxLayout()

            self.tabs = QTabWidget()
            self.setCentralWidget(self.tabs)
            self.tabs.setTabsClosable(True)
            self.tabs.tabCloseRequested.connect(self.close_tab)

            self.create_new_tab()
            self.tabs.tabBarDoubleClicked.connect(self.rename_tab)

            corner_container = QWidget()
            corner_layout = QHBoxLayout(corner_container)
            corner_layout.setContentsMargins(0, 0, 0, 0)  
            corner_layout.setSpacing(5) 


            # add_save_btn = QPushButton("Save Tab")
            # # add_save_btn.clicked.connect(self.save_tab_data)
            # corner_layout.addWidget(add_save_btn)
            #self.tabs.setCornerWidget(add_save_btn, Qt.TopRightCorner)

            add_tab_btn = QPushButton("New Tab +")
            add_tab_btn.clicked.connect(self.create_new_tab)
            corner_layout.addWidget(add_tab_btn)
            #self.tabs.setCornerWidget(add_tab_btn, Qt.TopRightCorner)

            self.tabs.setCornerWidget(corner_container, Qt.TopRightCorner)

            main_layout.addWidget(self.tabs)
            main_widget.setLayout(main_layout)
            self.setCentralWidget(main_widget)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Something went wrong : {str(e)}")
            helpercls.log(function_name='init_ui', args=[], exception=e)

    def create_new_tab(self, tab_name = None, tab_id = None):
        try:
        
            new_tab = GRPCTab(self.tabs)
            if tab_name:
                tab_text = tab_name
            else:
                tab_text = f"Tab {self.tab_counter}"
            index = self.tabs.addTab(new_tab, tab_text)
            self.tabs.setCurrentIndex(index)
            if tab_id:
                self.tabs.tabBar().setTabData(index, tab_id)
            self.tab_counter += 1

            if tab_name:
                return new_tab
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Something went wrong : {str(e)}")
            helpercls.log(function_name='create_new_tab', args=[], exception=e)
    
    def get_tab_id_by_index(self, index):
        try:
            return self.tabs.tabData(index)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Something went wrong : {str(e)}")
            helpercls.log(function_name='get_tab_id_by_index', args=[], exception=e)

    def close_tab(self, index):        
        try:
            if self.tabs.count() == 1:
                return

            # Show confirmation dialog
            reply = QMessageBox.question(
                self,
                "Confirm Close",
                f"Are you sure you want to close tab '{self.tabs.tabText(index)}'?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )

            # Only close if user clicks Yes
            if reply == QMessageBox.Yes:
                self.tabs.removeTab(index)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Something went wrong : {str(e)}")
            helpercls.log(function_name='close_tab', args=[], exception=e)

    def rename_tab(self, index):
        try:
            if index < 0:
                return

            old_name = self.tabs.tabText(index)

            # Create a custom dialog that appears near the tab
            dialog = QDialog(self)
            dialog.setWindowFlags(Qt.WindowType.FramelessWindowHint | Qt.WindowType.Popup)
            dialog.setModal(True)
            
            layout = QVBoxLayout(dialog)
            editor = QLineEdit(old_name, dialog)
            editor.setAlignment(Qt.AlignmentFlag.AlignCenter)
            editor.selectAll()
            
            layout.addWidget(editor)
            dialog.setLayout(layout)
            
            # Position dialog near the tab
            tab_rect = self.tabs.tabBar().tabRect(index)
            global_pos = self.tabs.tabBar().mapToGlobal(tab_rect.topLeft())
            dialog.move(global_pos.x(), global_pos.y() + tab_rect.height())
            dialog.resize(tab_rect.width(), 30)
            
            def accept_edit():
                new_name = editor.text().strip()
                if new_name:
                    self.tabs.setTabText(index, new_name)
                dialog.accept()
            
            def reject_edit():
                dialog.reject()
            
            editor.returnPressed.connect(accept_edit)
            editor.editingFinished.connect(accept_edit)
            
            # Close dialog when focus is lost
            def focus_out_event(event):
                accept_edit()
                QLineEdit.focusOutEvent(editor, event)
            
            editor.focusOutEvent = focus_out_event
            
            # Show dialog
            dialog.exec()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Something went wrong : {str(e)}")
            helpercls.log(function_name='rename_tab', args=[], exception=e)


    def show_certificate_dialog(self):
        try:
            dialog = CertificateDialog(self)
            if dialog.exec_():
                self.ssl_credentials = dialog.get_credentials()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Something went wrong : {str(e)}")
            helpercls.log(function_name='show_certificate_dialog', args=[], exception=e)

    def closeEvent(self, event):
        try:
            reply = QMessageBox.question(
                self,
                "Exit Confirmation",
                "Are you sure you want to exit?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                helpercls.cleanup()
                event.accept()  # allow closing
            else:
                event.ignore()  # cancel closing
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Something went wrong : {str(e)}")
            helpercls.log(function_name='closeEvent', args=[], exception=e)



# if __name__ == "__main__":
#     try:
#         app = QApplication(sys.argv)
#         app.setWindowIcon(QIcon('UI/icon.png'))
#         client = gRPCClient()
#         client.show()
#         sys.exit(app.exec_())
#     except Exception as e:
#         QMessageBox.critical("Error", f"Something went wrong : {str(e)}")
#         helpercls.log(function_name='app start', args=[], exception=e)
